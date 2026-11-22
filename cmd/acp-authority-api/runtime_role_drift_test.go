package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAuthorityHTTPRejectsRuntimeRoleDrift exercises the real TLS1.3/mTLS
// listener and an independently authenticated PostgreSQL LOGIN. The service
// must stop exposing even negative authority lookup results as soon as its
// database role gains extra privileges, without a process restart or a new
// connection. The 403 positive control is a nonexistent, correctly scoped
// RunIntent; the publication endpoint is enabled without any existing
// RunIntent, so neither route can publish an effect or signed receipt.
func TestAuthorityHTTPRejectsRuntimeRoleDrift(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	schema, role := "acp_role_drift_"+suffix, "acp_drift_reader_"+suffix
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	migrator, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := runpg.Migrate(ctx, migrator); err != nil {
		migrator.Close()
		t.Fatal(err)
	}
	migrator.Close()

	passwordBytes := make([]byte, 24)
	if _, err := rand.Read(passwordBytes); err != nil {
		t.Fatal(err)
	}
	password := fmt.Sprintf("%x", passwordBytes)
	if _, err := admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(context.Background(), "DROP OWNED BY "+role); err != nil {
			t.Errorf("drop role grants: %v", err)
		}
		if _, err := admin.Exec(context.Background(), "DROP ROLE "+role); err != nil {
			t.Errorf("drop test role: %v", err)
		}
	}()

	relations := []string{
		"run_intents", "admission_tenants", "admission_projects",
		"admission_principals", "admission_memberships",
		"admission_releases", "admission_sessions",
	}
	for _, name := range relations {
		if _, err := admin.Exec(ctx, "GRANT SELECT ON "+schema+"."+name+" TO "+role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, "GRANT USAGE ON SCHEMA "+schema+" TO "+role); err != nil {
		t.Fatal(err)
	}

	roleURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	roleURL.User = url.UserPassword(role, password)
	q := roleURL.Query()
	q.Set("search_path", schema)
	roleURL.RawQuery = q.Encode()

	// Fully verified client-side TLS, with an ephemeral CA and a SPIFFE URI
	// on the client certificate. This is a real network handshake, not an
	// artificially populated http.Request.TLS field.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ACP drift test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	mint := func(template *x509.Certificate) ([]byte, []byte) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	}
	peer := "spiffe://tests.example/authority/reader"
	peerURI, err := url.Parse(peer)
	if err != nil {
		t.Fatal(err)
	}
	serverPEM, serverKey := mint(&x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	clientPEM, clientKey := mint(&x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "workload"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		URIs: []*url.URL{peerURI}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	tmp := t.TempDir()
	certPath, keyPath, caPath := filepath.Join(tmp, "server.crt"), filepath.Join(tmp, "server.key"), filepath.Join(tmp, "client-ca.crt")
	for _, item := range []struct {
		path string
		data []byte
	}{
		{certPath, serverPEM}, {keyPath, serverKey}, {caPath, pemCA},
	} {
		if err := os.WriteFile(item.path, item.data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Configure a real publisher as well as the plain Run Authority route.
	// With no accepted RunIntent, neither route can produce a publication.
	releaseDirectory := filepath.Join(tmp, "releases")
	if err := os.Mkdir(releaseDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	publicationKey := filepath.Join(tmp, "publication.seed")
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicationKey, seed, 0600); err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := tls.X509KeyPair(clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemCA) {
		t.Fatal("invalid test root CA")
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots,
			Certificates: []tls.Certificate{clientCertificate},
		}},
	}
	defer client.CloseIdleConnections()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(ctx)
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- serve(serverCtx, config{
			dsn: roleURL.String(), cert: certPath, key: keyPath, ca: caPath,
			peer: peer, tenant: "tenant-drift", address: addr,
			releaseDirectory: releaseDirectory, publicationKey: publicationKey,
		})
	}()
	defer func() {
		stopServer()
		select {
		case err := <-serverErrors:
			if err != nil {
				t.Errorf("shutdown authority listener: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("authority listener did not stop")
		}
	}()

	id := "00000000-0000-4000-8000-000000000001"
	endpoint := "https://" + addr + "/internal/v1/run-authority/" + id +
		"?run_id=" + id + "&request_digest=sha256:" + strings.Repeat("a", 64)
	publicationEndpoint := strings.Replace(endpoint, "/internal/v1/run-authority/",
		"/internal/v1/decision-publication/", 1)
	getStatus := func(target string) (int, error) {
		resp, err := client.Get(target)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	// Wait only for the listener to start; never mask unexpected HTTP codes.
	var status int
	for deadline := time.Now().Add(8 * time.Second); ; {
		status, err = getStatus(endpoint)
		if err == nil {
			break
		}
		select {
		case serverErr := <-serverErrors:
			t.Fatalf("authority listener exited: %v", serverErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("authority listener failed to start: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected valid mTLS and missing RunIntent denial: HTTP %d", status)
	}
	checkBothRoutes := func(phase string, want int) {
		t.Helper()
		for _, route := range []struct {
			name, endpoint string
		}{
			{"run-authority", endpoint},
			{"decision-publication", publicationEndpoint},
		} {
			got, err := getStatus(route.endpoint)
			if err != nil || got != want {
				t.Fatalf("%s %s: HTTP %d, want %d: %v", phase, route.name, got, want, err)
			}
		}
	}
	checkBothRoutes("before-grant", http.StatusForbidden)
	// On the same running process and reused TLS/DB connection pool, make
	// the role overprivileged *after* startup. The next validated request
	// must fail closed, rather than returning the old negative lookup result.
	if _, err := admin.Exec(ctx, "GRANT SELECT ON "+schema+".outbox_events TO "+role); err != nil {
		t.Fatal(err)
	}
	checkBothRoutes("after-grant", http.StatusServiceUnavailable)
	if _, err := admin.Exec(ctx, "REVOKE SELECT ON "+schema+".outbox_events FROM "+role); err != nil {
		t.Fatal(err)
	}
	checkBothRoutes("after-revoke", http.StatusForbidden)

	// Loss of a mandatory catalog SELECT privilege must also be detected
	// before reading the RunIntent: a missing RunIntent must not camouflage
	// a broken authority-service database identity as normal HTTP 403.
	if _, err := admin.Exec(ctx, "REVOKE SELECT ON "+schema+".admission_sessions FROM "+role); err != nil {
		t.Fatal(err)
	}
	checkBothRoutes("after-required-select-revocation", http.StatusServiceUnavailable)
	if _, err := admin.Exec(ctx, "GRANT SELECT ON "+schema+".admission_sessions TO "+role); err != nil {
		t.Fatal(err)
	}
	checkBothRoutes("after-required-select-restore", http.StatusForbidden)

	// NOINHERIT membership with SET ROLE potential is dangerous even if it
	// does not make the reader's present table SELECT result change. Detect
	// privilege escalation of the actual live LOGIN, not only table grants.
	if _, err := admin.Exec(ctx, "GRANT pg_read_all_data TO "+role+" WITH INHERIT FALSE, SET TRUE"); err != nil {
		t.Fatal(err)
	}
	checkBothRoutes("after-role-membership-grant", http.StatusServiceUnavailable)
	if _, err := admin.Exec(ctx, "REVOKE pg_read_all_data FROM "+role); err != nil {
		t.Fatal(err)
	}
	checkBothRoutes("after-role-membership-revoke", http.StatusForbidden)
}
