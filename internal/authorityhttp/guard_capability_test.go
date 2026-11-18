package authorityhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGuardCapabilityListenerRejectsMissingAuthorityOrForwardedIdentity(t *testing.T) {
	if _, err := NewGuardCapabilityHandler(nil, nil, "spiffe://example.org/ns/guard/sa/engageguard", "tenant-a"); err == nil {
		t.Fatal("unconfigured Guard capability listener started")
	}
	// No TLS handshake, even a forwarded certificate is untrusted.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if verifiedPeer(r.TLS, "spiffe://example.org/ns/guard/sa/engageguard") {
			t.Fatal("forwarded identity forged verified TLS chain")
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	r := httptest.NewRequest(http.MethodPost, GuardCapabilityPath, nil)
	r.Header.Set("X-Forwarded-Client-Cert", "spiffe://example.org/ns/guard/sa/engageguard")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("untrusted forwarded certificate was accepted")
	}
}

func TestGuardCapabilityRequestRejectsCallerAuthorityFields(t *testing.T) {
	q := GuardCapabilityRequest{
		SchemaVersion: GuardCapabilitySchema,
		RunID:         "11111111-1111-4111-8111-111111111111",
		AgentID:       "agent-1", AgentReleaseID: "release-1",
		SessionID: "session-1", CapabilityID: "sre.metrics.read",
		CapabilityVersion: "1.0.0", ResourceRef: "payments",
	}
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	q.ResourceRef = "other service"
	if q.Validate() == nil {
		t.Fatal("unbounded resource selector accepted")
	}
}
