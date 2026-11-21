package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func completeEnv() map[string]string {
	return map[string]string{
		"ACP_GOAL_LISTEN_ADDR":              "127.0.0.1:9443",
		"ACP_GOAL_TLS_CERT_FILE":            "/tmp/acp-test-cert",
		"ACP_GOAL_TLS_KEY_FILE":             "/tmp/acp-test-key",
		"ACP_GOAL_PG_DSN_FILE":              "/tmp/acp-test-pg-dsn",
		"ACP_GOAL_OAUTH_CA_FILE":            "/tmp/acp-test-oauth-ca",
		"ACP_GOAL_OAUTH_ENDPOINT":           "https://issuer.example/introspect",
		"ACP_GOAL_OAUTH_ISSUER":             "https://issuer.example",
		"ACP_GOAL_OAUTH_AUDIENCE":           "acp-control-plane",
		"ACP_GOAL_OAUTH_CLIENT_ID":          "acp",
		"ACP_GOAL_OAUTH_CLIENT_SECRET_FILE": "/tmp/acp-test-oauth-secret",
		"ACP_GOAL_TENANT_ID":                "tenant-a",
		"ACP_GOAL_PROJECT_ID":               "project-a",
		"ACP_GOAL_AGENT_ID":                 "coding",
		"ACP_GOAL_RELEASE_ID":               "release-a",
		"ACP_GOAL_SESSION_ID":               "session-a",
		"ACP_GOAL_GITHUB_REPOSITORY":        "example/repository",
		"ACP_GOAL_TARGET_BRANCH":            "main",
		"ACP_GOAL_RULES_DIGEST":             "sha256:" + strings.Repeat("1", 64),
		"ACP_GOAL_MAX_TOKENS":               "2000",
		"ACP_GOAL_MAX_RUNTIME_SECONDS":      "1200",
		"ACP_GOAL_MAX_SANDBOX_SECONDS":      "600",
	}
}

func configuredEnv(m map[string]string) func(string) string {
	return func(key string) string { return m[key] }
}

func TestReadConfigRequiresExplicitLoopbackAndTrustedScope(t *testing.T) {
	env := completeEnv()
	if _, err := readConfig(configuredEnv(env)); err != nil {
		t.Fatalf("explicit safe configuration rejected: %v", err)
	}
	for _, tc := range []struct {
		name, key, replacement string
	}{
		{"missing certificate", "ACP_GOAL_TLS_CERT_FILE", ""},
		{"missing database secret", "ACP_GOAL_PG_DSN_FILE", ""},
		{"missing IdP trust", "ACP_GOAL_OAUTH_CA_FILE", ""},
		{"missing OAuth secret", "ACP_GOAL_OAUTH_CLIENT_SECRET_FILE", ""},
		{"missing tenant", "ACP_GOAL_TENANT_ID", ""},
		{"wildcard listener", "ACP_GOAL_LISTEN_ADDR", "0.0.0.0:9443"},
		{"external listener", "ACP_GOAL_LISTEN_ADDR", "192.0.2.1:9443"},
		{"hostname listener", "ACP_GOAL_LISTEN_ADDR", "localhost:9443"},
		{"non-TLS issuer", "ACP_GOAL_OAUTH_ISSUER", "http://issuer.example"},
		{"foreign repository", "ACP_GOAL_GITHUB_REPOSITORY", "../other"},
		{"invalid branch", "ACP_GOAL_TARGET_BRANCH", "../main"},
		{"invalid acceptance digest", "ACP_GOAL_RULES_DIGEST", "sha256:BAD"},
		{"unbounded tokens", "ACP_GOAL_MAX_TOKENS", "0"},
		{"unbounded runtime", "ACP_GOAL_MAX_RUNTIME_SECONDS", "999999999"},
		{"sandbox longer than run", "ACP_GOAL_MAX_SANDBOX_SECONDS", "9999"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := completeEnv()
			bad[tc.key] = tc.replacement
			if _, err := readConfig(configuredEnv(bad)); err == nil {
				t.Fatalf("unsafe %s configuration accepted", tc.name)
			}
		})
	}
}

func TestSecretFilesMustBePrivateRegularNonempty(t *testing.T) {
	directory := t.TempDir()
	secret := filepath.Join(directory, "secret")
	if err := os.WriteFile(secret, []byte("private-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readSecretFile(secret); err != nil || got != "private-value" {
		t.Fatalf("private credential unexpectedly rejected: %v", err)
	}
	if err := os.Chmod(secret, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(secret); err == nil {
		t.Fatal("world-readable credential accepted")
	}
	if err := os.Chmod(secret, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(secret); err == nil {
		t.Fatal("empty credential accepted")
	}
}

func TestServerFailsBeforeBindingWithMissingTLSFiles(t *testing.T) {
	c, err := readConfig(configuredEnv(completeEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if err := serve(context.Background(), c); err == nil {
		t.Fatal("host started without trusted TLS key material")
	}
}

func TestUnprotectedBranchOverrideRequiresDevelopmentEnvironment(t *testing.T) {
	env := completeEnv()
	env["ACP_GOAL_ALLOW_UNPROTECTED_TEST_BRANCH"] = "true"
	if _, err := readConfig(configuredEnv(env)); err == nil {
		t.Fatal("unprotected branch override accepted outside development environment")
	}
	env["ACP_GOAL_ENV"] = "production"
	if _, err := readConfig(configuredEnv(env)); err == nil {
		t.Fatal("unprotected branch override accepted in production")
	}
	env["ACP_GOAL_ENV"] = "development"
	if cfg, err := readConfig(configuredEnv(env)); err != nil {
		t.Fatalf("explicit development override rejected: %v", err)
	} else if cfg.policy.RequireProtectedBranch {
		t.Fatal("explicit development override did not disable branch-protection requirement")
	}
}

func TestSecretFilesRejectSymbolicLinks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "secret-link")
	if err := os.WriteFile(target, []byte("private-value"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(link); err == nil {
		t.Fatal("symbolic link to a private credential was accepted")
	}
}

func writeTestServerKeyPair(t *testing.T, directory string, notBefore, notAfter time.Time, dnsNames []string, ips []net.IP) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ACP test server"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestLoadServerCertificateRequiresCurrentMatchingSAN(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		dnsNames  []string
		ips       []net.IP
		wantErr   bool
	}{
		{name: "matching loopback IP", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), ips: []net.IP{net.ParseIP("127.0.0.1")}},
		{name: "wrong DNS identity", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), dnsNames: []string{"localhost"}, wantErr: true},
		{name: "expired", notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour), ips: []net.IP{net.ParseIP("127.0.0.1")}, wantErr: true},
		{name: "not yet valid", notBefore: now.Add(time.Hour), notAfter: now.Add(2 * time.Hour), ips: []net.IP{net.ParseIP("127.0.0.1")}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			certPath, keyPath := writeTestServerKeyPair(t, directory, tc.notBefore, tc.notAfter, tc.dnsNames, tc.ips)
			certificate, err := loadServerCertificate(certPath, keyPath, "127.0.0.1", now)
			if tc.wantErr && err == nil {
				t.Fatal("invalid server certificate was accepted")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("valid server certificate rejected: %v", err)
			}
			if !tc.wantErr && certificate.Leaf == nil {
				t.Fatal("parsed leaf certificate was not retained")
			}
		})
	}
}

func TestVerifyAuthoritySchemaRequiresLatestAdmissionMigration(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL via PGTEST_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("test_goal_api_schema_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	}()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := runpg.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuthoritySchema(ctx, pool); err != nil {
		t.Fatalf("fully migrated ACP authority schema rejected: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE schema_migrations SET checksum=repeat('0',64) WHERE version=12"); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuthoritySchema(ctx, pool); err == nil {
		t.Fatal("schema with a modified migration checksum was accepted")
	}
	if _, err := pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version=12"); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuthoritySchema(ctx, pool); err == nil {
		t.Fatal("schema missing admission-origin migration was accepted")
	}
}
