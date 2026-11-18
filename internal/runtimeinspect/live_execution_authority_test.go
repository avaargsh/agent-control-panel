package runtimeinspect

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This is a real TLS listener using the same actual OAuth-admitted and
// reconciled ACP Run, never a fake repository or caller tenant assertion.
func goldenReleaseArtifact(t *testing.T, target runintent.Intent) ([]byte, string) {
	t.Helper()
	// These are isolated operator-provisioned read-only contracts. No
	// executor or evidence producer is claimed by this publication test.
	now := time.Now().UTC().Truncate(time.Second)
	config := authorityhttp.ReleaseConfig{
		SchemaVersion: "acp.release-publication.v1", TenantID: target.TenantID, ProjectID: target.ProjectID,
		AgentID: target.AgentID, AgentReleaseID: target.ReleaseID, PolicyRevision: target.PrincipalSnapshot.PolicyRevision,
		CatalogVersion: "1.0.0", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Services: []string{"payments"}, Capabilities: []authorityhttp.CapabilityContract{},
	}
	for _, id := range []string{"sre.changes.read", "sre.logs.read", "sre.metrics.read"} {
		config.Capabilities = append(config.Capabilities, authorityhttp.CapabilityContract{
			ID: id, Version: "1.0.0", InputSchema: json.RawMessage(`{"type":"object","required":["service"]}`),
			OutputSchema: json.RawMessage(`{"type":"object"}`),
			EffectClass:  "read_only", Idempotency: "safe", TenantScoped: true,
		})
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return raw, "sha256:" + hex.EncodeToString(sum[:])
}

func newLiveExecutionAuthorityReader(t *testing.T, pool *pgxpool.Pool, dsn, runtimeDSN string, repo *runpg.Repository, ref runpg.ExecutionAuthorityRef, admitted runintent.Intent, releaseArtifact []byte) (func(int), []string) {
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
	releaseDir := filepath.Join(dir, "releases")
	if err := os.Mkdir(releaseDir, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(releaseArtifact)
	configDigest := hex.EncodeToString(sum[:])
	artifactPath := filepath.Join(releaseDir, configDigest+".json")
	if err := os.WriteFile(artifactPath, releaseArtifact, 0600); err != nil {
		t.Fatal(err)
	}
	signingPublic, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seedFile := filepath.Join(dir, "publication.seed")
	if err := os.WriteFile(seedFile, signingKey.Seed(), 0600); err != nil {
		t.Fatal(err)
	}
	clear(signingKey)
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
		"ACP_AUTHORITY_LISTEN_ADDR="+addr, "ACP_AUTHORITY_RELEASE_DIRECTORY="+releaseDir,
		"ACP_AUTHORITY_PUBLICATION_KEY="+seedFile)
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
		raw, err := io.ReadAll(io.LimitReader(res.Body, 512*1024+1))
		if err != nil || len(raw) > 512*1024 || res.StatusCode != want || res.Header.Get("Cache-Control") != "no-store" {
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
	pubPath := strings.Replace(path, authorityhttp.PathPrefix, authorityhttp.PublicationPathPrefix, 1)
	verifyPublication := func(body string) {
		t.Helper()
		var signed authorityhttp.SignedPublication
		if err := json.Unmarshal([]byte(body), &signed); err != nil || !ed25519.Verify(signingPublic, signed.Payload, signed.Signature) {
			t.Fatal("actual ACP service did not return authentic signed publication")
		}
		var p authorityhttp.Publication
		if err := json.Unmarshal(signed.Payload, &p); err != nil ||
			p.Authority.RunID != ref.RunID || p.Authority.RunIntentID != ref.RunIntentID ||
			p.Authority.RequestDigest != ref.RequestDigest || p.Authority.ConfigDigest != "sha256:"+configDigest ||
			p.Context.Authority != p.Authority || p.Context.Service != "payments" || p.Context.Objective != "sre_incident_triage" ||
			!bytes.Equal(p.CapabilityContent, releaseArtifact) || p.CapabilitySnapshot.SHA256 != configDigest ||
			len(p.Capabilities) != 3 {
			t.Fatal("signed publication differs from actual admitted release or persisted Run")
		}
		contextHash := sha256.Sum256(p.ContextContent)
		if p.ContextSnapshot.SHA256 != hex.EncodeToString(contextHash[:]) {
			t.Fatal("context content digest mismatch")
		}
	}
	first := call(h, http.MethodGet, pubPath, http.StatusOK)
	verifyPublication(first)
	// Separate Decision verifier executable, compiled from pinned actual
	// Decision repository. Expected binding is the authentic admitted intent
	// and recovered Runtime receipt, never parsed from signed publication.
	decisionBin := os.Getenv("ACP_DECISION_PUBLICATION_TEST_BIN")
	if decisionBin == "" {
		t.Fatal("Golden Path requires independent Decision verifier binary")
	}
	expected, err := json.Marshal(map[string]string{
		"tenant_id": admitted.TenantID, "run_intent_id": admitted.ID, "run_id": ref.RunID,
		"request_digest": admitted.RequestDigest, "project_id": admitted.ProjectID, "agent_id": admitted.AgentID,
		"agent_release_id": admitted.ReleaseID, "session_id": admitted.SessionID,
		"subject_id": admitted.PrincipalSnapshot.SubjectID, "actor_id": admitted.PrincipalSnapshot.ActorID,
		"policy_revision": admitted.PrincipalSnapshot.PolicyRevision, "config_digest": admitted.PrincipalSnapshot.ConfigDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	wireFile, publicFile, bindingFile := filepath.Join(dir, "signed.json"), filepath.Join(dir, "acp-public.key"), filepath.Join(dir, "expected.json")
	for path, raw := range map[string][]byte{wireFile: []byte(first), publicFile: signingPublic, bindingFile: expected} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	verify := exec.Command(decisionBin, "-test.v", "-test.run=^TestExternalACPSignedPublication$", "-test.timeout=30s")
	verify.Env = append(goldenPathChildEnvironment(),
		"DECISION_EXTERNAL_ACP_PUBLICATION=1", "DECISION_PUBLICATION_FILE="+wireFile,
		"DECISION_ACP_PINNED_KEY_FILE="+publicFile, "DECISION_EXPECTED_BINDING_FILE="+bindingFile)
	output, err := verify.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: TestExternalACPSignedPublication ")) {
		t.Fatalf("independent Decision verifier failed: %v %s", err, output)
	}
	t.Logf("independent Decision evidence:\n%s", output)
	if second := call(h, http.MethodGet, pubPath, http.StatusOK); first != second {
		t.Fatal("signed publication not stable for exact same Run")
	}
	// Corrupt or remove trusted bytes: cannot sign a replacement under the
	// original admission config digest, even if the catalog is still active.
	if err := os.WriteFile(artifactPath, append(bytes.Clone(releaseArtifact), ' '), 0600); err != nil {
		t.Fatal(err)
	}
	call(h, http.MethodGet, pubPath, http.StatusServiceUnavailable)
	if err := os.WriteFile(artifactPath, releaseArtifact, 0600); err != nil {
		t.Fatal(err)
	}
	if got := call(h, http.MethodGet, pubPath, http.StatusOK); got != first {
		t.Fatal("restored exact content did not restore original publication")
	}
	t.Logf("actual ACP signed Context/Capability publication verified for Run %s", ref.RunID)
	var liveEnv []string
	if os.Getenv("ACP_LIVE_DECISION") == "1" {
		runtimeOrigin, runtimeCA := startLiveRuntimeDecisionAuthority(t, runtimeDSN, dir, caFile, ref)
		decisionCertFile, decisionKeyFile := filepath.Join(dir, "decision-client.pem"), filepath.Join(dir, "decision-client.key")
		writeProcessCertificate(t, decisionCertFile, decisionKeyFile, clientCert)
		rootFile := filepath.Join(dir, "decision-roots.pem")
		acpCA, err := os.ReadFile(caFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rootFile, append(acpCA, runtimeCA...), 0600); err != nil {
			t.Fatal(err)
		}
		liveEnv = []string{
			"RUNTIME_EXTERNAL_LIVE_DECISION=1",
			"DECISION_EXTERNAL_LIVE_CORE_BIN=" + os.Getenv("ACP_DECISION_LIVE_CORE_BIN"),
			"DECISION_LIVE_AGENT=" + admitted.AgentID,
			"DECISION_LIVE_ROOTS=" + rootFile,
			"DECISION_LIVE_CLIENT_CA=" + caFile,
			"DECISION_LIVE_CLIENT_CERT=" + decisionCertFile, "DECISION_LIVE_CLIENT_KEY=" + decisionKeyFile,
			"DECISION_LIVE_ACP_PUBLIC_KEY=" + publicFile, "DECISION_LIVE_ACP_ORIGIN=" + origin,
			"DECISION_LIVE_RUNTIME_ORIGIN=" + runtimeOrigin,
			"DECISION_LIVE_DATABASE_URL=" + os.Getenv("ACP_DECISION_DATABASE_URL"),
		}
		if os.Getenv("ACP_LIVE_CONTINUATION") == "1" {
			liveEnv = append(liveEnv, "RUNTIME_EXTERNAL_LIVE_CONTINUATION=1")
		}
	}
	return func(want int) {
		t.Helper()
		body := call(h, http.MethodGet, path, want)
		pubBody := call(h, http.MethodGet, pubPath, want)
		if want != http.StatusOK {
			return
		}
		verifyPublication(pubBody)
		if pubBody != first {
			t.Fatal("publication changed after catalog restoration")
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
	}, liveEnv
}
