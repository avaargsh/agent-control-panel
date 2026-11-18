package main

import "testing"

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
