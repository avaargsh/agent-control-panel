package admission

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Both tenants have legitimate, indistinguishable resource names and
// idempotency keys. A negative test with only a missing target would not
// demonstrate that the other tenant's resources actually exist.
func TestTwoRealPolicyTenantsDoNotConfuseIdentitiesOrRequests(t *testing.T) {
	resource := Target{ProjectID: "shared-project", AgentID: "shared-agent",
		ReleaseID: "shared-release", SessionID: "shared-session"}
	a, b := resource, resource
	a.TenantID, b.TenantID = "tenant-a", "tenant-b"
	issuer := testIssuer
	alice := Identity{Issuer: issuer, Subject: "alice", ClientID: "client-a",
		Scope: RunIntentCreateScope, ExpiresAt: time.Now().Add(30 * time.Minute)}
	bob := Identity{Issuer: issuer, Subject: "bob", ClientID: "client-b",
		Scope: RunIntentCreateScope, ExpiresAt: time.Now().Add(30 * time.Minute)}

	policy, err := NewExactPolicy(PolicySnapshot{
		Revision: "tenant-matrix-1", ExpiresAt: time.Now().Add(30 * time.Minute),
		Grants: []PolicyEntry{
			{Issuer: issuer, Subject: alice.Subject, ClientID: alice.ClientID,
				Target: a, PrincipalID: "alice-principal", SubjectID: "alice-subject",
				ConfigDigest: "sha256:" + strings.Repeat("a", 64)},
			{Issuer: issuer, Subject: bob.Subject, ClientID: bob.ClientID,
				Target: b, PrincipalID: "bob-principal", SubjectID: "bob-subject",
				ConfigDigest: "sha256:" + strings.Repeat("b", 64)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"objective":"triage"}`)
	var digestA, digestB string
	for _, tc := range []struct {
		name     string
		identity Identity
		target   Target
		allow    bool
	}{
		{"alice-own", alice, a, true},
		{"bob-own", bob, b, true},
		{"alice-forges-b", alice, b, false},
		{"bob-forges-a", bob, a, false},
		{"alice-reuses-b-client", Identity{Issuer: issuer, Subject: "alice",
			ClientID: bob.ClientID, Scope: RunIntentCreateScope,
			ExpiresAt: alice.ExpiresAt}, b, false},
		{"bob-reuses-a-client", Identity{Issuer: issuer, Subject: "bob",
			ClientID: alice.ClientID, Scope: RunIntentCreateScope,
			ExpiresAt: bob.ExpiresAt}, a, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &inputCaptureStore{}
			svc := New(store, NewBearerResolver(policyTestAuthenticator{tc.identity}, policy, "opaque-token"))
			req := Request{Target: tc.target, IdempotencyKey: "identical-idempotency-key"}
			got, created, err := svc.AdmitWithInput(context.Background(), req, raw)
			if !tc.allow {
				if !errors.Is(err, ErrPolicyDenied) || created || store.calls != 0 {
					t.Fatalf("foreign tenant wrote an intent: created=%v calls=%d err=%v", created, store.calls, err)
				}
				return
			}
			if err != nil || !created || store.calls != 1 ||
				got.TenantID != tc.target.TenantID ||
				got.ProjectID != tc.target.ProjectID ||
				got.RequestDigest == "" {
				t.Fatalf("own tenant failed admission or binding: created=%v intent=%+v err=%v", created, got, err)
			}
			if tc.target.TenantID == a.TenantID {
				digestA = got.RequestDigest
			} else {
				digestB = got.RequestDigest
			}
		})
	}
	if digestA == "" || digestB == "" || digestA == digestB {
		t.Fatal("same raw input and idempotency must be cryptographically bound to distinct tenants")
	}
}
