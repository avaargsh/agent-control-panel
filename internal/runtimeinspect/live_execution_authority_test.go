package runtimeinspect

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/authorityhttp"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This is a real TLS listener using the same actual OAuth-admitted and
// reconciled ACP Run, never a fake repository or caller tenant assertion.
func newLiveExecutionAuthorityReader(t *testing.T, pool *pgxpool.Pool, dsn string, repo *runpg.Repository, ref runpg.ExecutionAuthorityRef) func(int) {
	t.Helper()
	const peer = "spiffe://example.org/decision"
	roots, serverCert, clientCert := testSPIFFECertificatesFor(t, "spiffe://example.org/acp", peer)
	binary := os.Getenv("ACP_AUTHORITY_API_BIN")
	if binary == "" {
		t.Fatal("live Golden Path requires the compiled ACP authority service")
	}
	ctx := context.Background()
	// Dedicated disposable LOGIN: no DDL or writes. Provision the role only
	// inside the isolated Golden Path fixture; the API process never migrates.
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(random[:])
	role := "acp_authority_" + password[:16]
	quoted := pgx.Identifier{role}.Sanitize()
	for _, stmt := range []string{
		"CREATE ROLE " + quoted + " LOGIN PASSWORD '" + password + "'",
		"GRANT USAGE ON SCHEMA public TO " + quoted,
		"GRANT SELECT ON run_intents,admission_tenants,admission_projects,admission_principals,admission_memberships,admission_releases,admission_sessions TO " + quoted,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal("could not provision isolated authority reader role")
		}
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		admin, err := pgx.Connect(cleanupCtx, dsn)
		if err != nil {
			t.Error("could not connect for isolated role cleanup")
			return
		}
		defer admin.Close(cleanupCtx)
		if _, err := admin.Exec(cleanupCtx, "DROP OWNED BY "+quoted); err != nil {
			t.Error("could not release isolated role grants")
		}
		if _, err := admin.Exec(cleanupCtx, "DROP ROLE "+quoted); err != nil {
			t.Error("could not remove isolated authority LOGIN")
		}
	})
	dbURL, err := url.Parse(dsn)
	if err != nil || dbURL.Host == "" {
		t.Fatal("Golden Path requires isolated PostgreSQL URL")
	}
	dbURL.User = url.UserPassword(role, password)
	readDSN := dbURL.String()
	readConn, err := pgx.Connect(ctx, readDSN)
	if err != nil {
		t.Fatal("isolated read role login failed")
	}
	if _, err := readConn.Exec(ctx, "UPDATE run_intents SET updated_at=clock_timestamp() WHERE false"); err == nil {
		readConn.Close(ctx)
		t.Fatal("authority reader obtained write privilege")
	}
	_ = readConn.Close(ctx)
	dir := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(dir, "acp-authority.pem"), filepath.Join(dir, "acp-authority.key"), filepath.Join(dir, "ca.pem")
	writeProcessCertificate(t, certFile, keyFile, serverCert)
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Certificate[1]}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	origin := "https://" + addr
	proc := exec.Command(binary)
	proc.Env = append(goldenPathChildEnvironment(),
		"ACP_AUTHORITY_DATABASE_URL="+readDSN, "ACP_AUTHORITY_TLS_CERT="+certFile,
		"ACP_AUTHORITY_TLS_KEY="+keyFile, "ACP_AUTHORITY_CLIENT_CA="+caFile,
		"ACP_AUTHORITY_PEER_SPIFFE_ID="+peer, "ACP_AUTHORITY_TENANT="+ref.TenantID,
		"ACP_AUTHORITY_LISTEN_ADDR="+addr)
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Process.Kill(); _ = proc.Wait() })
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCert},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 ||
				len(state.PeerCertificates[0].URIs) != 1 ||
				state.PeerCertificates[0].URIs[0].String() != "spiffe://example.org/acp" {
				return errors.New("unexpected ACP authority identity")
			}
			return nil
		},
	}}
	t.Cleanup(transport.CloseIdleConnections)
	h := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	path := "/internal/v1/run-authority/" + ref.RunIntentID + "?" + url.Values{
		"run_id": {ref.RunID}, "request_digest": {ref.RequestDigest},
	}.Encode()
	call := func(client *http.Client, method, target string, want int) string {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), method, origin+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Tenant-ID", "foreign")
		req.Header.Set("X-Forwarded-Client-Cert", peer)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(res.Body, 8193))
		if err != nil || res.StatusCode != want || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("live network authority expected %d, got %d: %v", want, res.StatusCode, err)
		}
		return string(raw)
	}
	ready := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		response, err := h.Get(origin + path)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("actual ACP read-only authority service did not become ready")
	}
	call(h, http.MethodGet, path+"&tenant_id=foreign", http.StatusBadRequest)
	call(h, http.MethodPost, path, http.StatusMethodNotAllowed)
	call(h, http.MethodGet, strings.Replace(path, ref.RunID, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1), http.StatusForbidden)
	badHandler, err := authorityhttp.NewHandler(repo, "spiffe://example.org/other", ref.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	badServer := httptest.NewUnstartedServer(badHandler)
	badServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, Certificates: []tls.Certificate{serverCert}}
	badServer.StartTLS()
	defer badServer.Close()
	badReq, err := http.NewRequest(http.MethodGet, badServer.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	badReq.Header.Set("X-Forwarded-Client-Cert", "spiffe://example.org/other")
	bad, err := h.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatal("real TLS wrong peer spoofed authority")
	}
	return func(want int) {
		t.Helper()
		body := call(h, http.MethodGet, path, want)
		if want != http.StatusOK {
			return
		}
		var wire map[string]any
		if json.Unmarshal([]byte(body), &wire) != nil || wire["schema_version"] != "acp.run-authority.v1" ||
			wire["tenant_id"] != ref.TenantID || wire["run_intent_id"] != ref.RunIntentID ||
			wire["run_id"] != ref.RunID || wire["request_digest"] != ref.RequestDigest ||
			wire["agent_id"] != "agent-1" || wire["session_id"] != "session-1" ||
			wire["agent_release_id"] != "release-1" || wire["policy_revision"] != "policy-revision-1" ||
			strings.Contains(body, "acp-ci-runner") || strings.Contains(body, "admission_issuer") ||
			strings.Contains(body, "execution_input") || strings.Contains(body, "permit") {
			t.Fatalf("invalid returned authority reference: %s", body)
		}
	}
}
