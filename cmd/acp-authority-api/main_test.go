package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGuardAuthorityRequiresDedicatedListenerAndLiveReleasePublication(t *testing.T) {
	env := map[string]string{
		"ACP_AUTHORITY_DATABASE_URL":   "postgres://local/isolated",
		"ACP_AUTHORITY_TLS_CERT":       "server.pem",
		"ACP_AUTHORITY_TLS_KEY":        "server.key",
		"ACP_AUTHORITY_CLIENT_CA":      "ca.pem",
		"ACP_AUTHORITY_PEER_SPIFFE_ID": "spiffe://example.org/decision",
		"ACP_AUTHORITY_TENANT":         "tenant-1",
		"ACP_AUTHORITY_LISTEN_ADDR":    "127.0.0.1:8444",
	}
	get := func(key string) string { return env[key] }
	if _, err := readConfig(get); err != nil {
		t.Fatal(err)
	}
	env["ACP_AUTHORITY_GUARD_PEER_SPIFFE_ID"] = "spiffe://example.org/ns/guard/sa/engageguard"
	if _, err := readConfig(get); err == nil {
		t.Fatal("Guard identity without dedicated listener accepted")
	}
	env["ACP_AUTHORITY_GUARD_LISTEN_ADDR"] = "127.0.0.1:8444"
	if _, err := readConfig(get); err == nil {
		t.Fatal("Guard shared Runtime/Decision authority socket")
	}
	env["ACP_AUTHORITY_GUARD_LISTEN_ADDR"] = "127.0.0.1:8445"
	if _, err := readConfig(get); err == nil {
		t.Fatal("Guard capability verified without immutable release publication")
	}
	env["ACP_AUTHORITY_RELEASE_DIRECTORY"] = "/tmp/release"
	env["ACP_AUTHORITY_PUBLICATION_KEY"] = "/tmp/key"
	c, err := readConfig(get)
	if err != nil || c.guardPeer != env["ACP_AUTHORITY_GUARD_PEER_SPIFFE_ID"] ||
		c.guardAddress != env["ACP_AUTHORITY_GUARD_LISTEN_ADDR"] {
		t.Fatalf("valid isolated Guard listener rejected: %+v %v", c, err)
	}
	delete(env, "ACP_AUTHORITY_GUARD_PEER_SPIFFE_ID")
	if _, err := readConfig(get); err == nil {
		t.Fatal("unbound Guard listener accepted")
	}
}

func TestGuardReadRoutesRequireFreshAuthorityRole(t *testing.T) {
	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/guard-capabilities:verify", nil)
	denied := httptest.NewRecorder()
	requireAuthorityReadRole(next, func(context.Context) error { return errors.New("role drift") }).ServeHTTP(denied, req)
	if denied.Code != http.StatusServiceUnavailable || called != 0 {
		t.Fatalf("Guard route bypassed role drift: status=%d calls=%d", denied.Code, called)
	}
	missing := httptest.NewRecorder()
	requireAuthorityReadRole(next, nil).ServeHTTP(missing, req)
	if missing.Code != http.StatusServiceUnavailable || called != 0 {
		t.Fatalf("Guard route accepted missing role guard: status=%d calls=%d", missing.Code, called)
	}
	ok := httptest.NewRecorder()
	requireAuthorityReadRole(next, func(context.Context) error { return nil }).ServeHTTP(ok, req)
	if ok.Code != http.StatusNoContent || called != 1 {
		t.Fatalf("Guard route rejected eligible reader: status=%d calls=%d", ok.Code, called)
	}
}


func TestCutoverObserverRequiresIndependentURLAndLogin(t *testing.T) {
	env := map[string]string{
		"ACP_AUTHORITY_DATABASE_URL":   "postgres://authority@db.example/authority",
		"ACP_AUTHORITY_TLS_CERT":       "server.pem",
		"ACP_AUTHORITY_TLS_KEY":        "server.key",
		"ACP_AUTHORITY_CLIENT_CA":      "ca.pem",
		"ACP_AUTHORITY_PEER_SPIFFE_ID": "spiffe://example.org/decision",
		"ACP_AUTHORITY_TENANT":         "tenant-1",
		"ACP_AUTHORITY_LISTEN_ADDR":    "127.0.0.1:8444",
	}
	get := func(key string) string { return env[key] }
	env["ACP_AUTHORITY_CUTOVER_OBSERVER_DATABASE_URL"] = "postgres://observer@db.example/authority"
	if _, err := readConfig(get); err == nil {
		t.Fatal("cutover observer URL without explicit LOGIN was accepted")
	}
	delete(env, "ACP_AUTHORITY_CUTOVER_OBSERVER_DATABASE_URL")
	env["ACP_AUTHORITY_CUTOVER_OBSERVER_LOGIN"] = "acp_cutover_reader"
	if _, err := readConfig(get); err == nil {
		t.Fatal("cutover observer LOGIN without independent URL was accepted")
	}
	env["ACP_AUTHORITY_CUTOVER_OBSERVER_DATABASE_URL"] = "postgres://observer@db.example/authority"
	c, err := readConfig(get)
	if err != nil || c.cutoverDSN != env["ACP_AUTHORITY_CUTOVER_OBSERVER_DATABASE_URL"] ||
		c.cutoverLogin != "acp_cutover_reader" {
		t.Fatalf("valid opt-in cutover observer configuration rejected: %+v %v", c, err)
	}
}
