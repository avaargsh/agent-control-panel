package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
