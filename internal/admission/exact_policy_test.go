package admission

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

func policyFixture() (PolicySnapshot, Identity, Request) {
	req, _ := fixture()
	req.RequestDigest = ""
	id := Identity{
		Issuer: testIssuer, Subject: "alice", ClientID: "approved-client",
		Scope: "openid acp:run-intent:create", ExpiresAt: time.Now().Add(time.Hour),
	}
	snapshot := PolicySnapshot{
		Revision: "revision-1", ExpiresAt: time.Now().Add(time.Hour),
		Grants: []PolicyEntry{{
			Issuer: id.Issuer, Subject: id.Subject, ClientID: id.ClientID,
			Target: req.Target, PrincipalID: "principal-alice", SubjectID: "subject-alice",
			ConfigDigest: "sha256:" + strings.Repeat("b", 64),
		}},
	}
	return snapshot, id, req
}

type policyTestAuthenticator struct{ identity Identity }

func (a policyTestAuthenticator) Authenticate(context.Context, string) (Identity, error) {
	return a.identity, nil
}

func TestExactPolicyAdmitsOnlyBoundDirectIdentityAndTarget(t *testing.T) {
	snapshot, id, req := policyFixture()
	policy, err := NewExactPolicy(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	store := &inputCaptureStore{}
	service := New(store, NewBearerResolver(policyTestAuthenticator{id}, policy, "fixture"))
	raw := []byte(`{"task":"inspect"}`)
	intent, created, err := service.AdmitWithInput(context.Background(), req, raw)
	if err != nil || !created || store.calls != 1 {
		t.Fatalf("admission failed: %v", err)
	}
	if intent.PrincipalID != "principal-alice" || intent.PrincipalSnapshot.SubjectID != "subject-alice" ||
		intent.PrincipalSnapshot.ActorID != "subject-alice" ||
		intent.PrincipalSnapshot.PolicyRevision != snapshot.Revision ||
		intent.PrincipalSnapshot.ConfigDigest != snapshot.Grants[0].ConfigDigest ||
		intent.PrincipalSnapshot.Version != runintent.PrincipalSnapshotVersion {
		t.Fatalf("incorrect authorized principal snapshot: %+v", intent.PrincipalSnapshot)
	}
	if err := runintent.VerifyExecutionInput(intent, raw); err != nil {
		t.Fatal(err)
	}
	req.RequestDigest = intent.RequestDigest
	if _, _, err := service.Admit(context.Background(), req); !errors.Is(err, ErrPolicyDenied) || store.calls != 1 {
		t.Fatalf("digest-only admission bypassed input policy: %v", err)
	}
}

func TestExactPolicyDeniesUnknownIdentityScopeAndResource(t *testing.T) {
	snapshot, id, req := policyFixture()
	policy, err := NewExactPolicy(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Identity, *Request)
	}{
		{"issuer", func(i *Identity, _ *Request) { i.Issuer = "https://other.example.test" }},
		{"subject", func(i *Identity, _ *Request) { i.Subject = "bob" }},
		{"client", func(i *Identity, _ *Request) { i.ClientID = "other-client" }},
		{"scope missing", func(i *Identity, _ *Request) { i.Scope = "" }},
		{"scope prefix", func(i *Identity, _ *Request) { i.Scope = "acp:run-intent:create-other" }},
		{"malformed scope", func(i *Identity, _ *Request) { i.Scope = "openid\tacp:run-intent:create" }},
		{"tenant", func(_ *Identity, r *Request) { r.Target.TenantID = "tenant-b" }},
		{"project", func(_ *Identity, r *Request) { r.Target.ProjectID = "project-b" }},
		{"agent", func(_ *Identity, r *Request) { r.Target.AgentID = "agent-b" }},
		{"release", func(_ *Identity, r *Request) { r.Target.ReleaseID = "release-b" }},
		{"session", func(_ *Identity, r *Request) { r.Target.SessionID = "session-b" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity, request := id, req
			tc.edit(&identity, &request)
			store := &inputCaptureStore{}
			svc := New(store, NewBearerResolver(policyTestAuthenticator{identity}, policy, "fixture"))
			_, _, err := svc.AdmitWithInput(context.Background(), request, []byte("{}"))
			if !errors.Is(err, ErrPolicyDenied) || store.calls != 0 {
				t.Fatalf("disallowed request wrote state: %v", err)
			}
		})
	}
}

func TestExactPolicyRejectsAmbiguousSnapshotAndExpires(t *testing.T) {
	snapshot, id, req := policyFixture()
	duplicate := snapshot
	duplicate.Grants = append(append([]PolicyEntry(nil), snapshot.Grants...), snapshot.Grants[0])
	if _, err := NewExactPolicy(duplicate); !errors.Is(err, ErrPolicyConfig) {
		t.Fatalf("duplicate grant accepted: %v", err)
	}
	conflicting := snapshot
	other := snapshot.Grants[0]
	other.Subject = "bob"
	other.ConfigDigest = "sha256:" + strings.Repeat("c", 64)
	conflicting.Grants = append(append([]PolicyEntry(nil), snapshot.Grants...), other)
	if _, err := NewExactPolicy(conflicting); !errors.Is(err, ErrPolicyConfig) {
		t.Fatalf("conflicting release configuration accepted: %v", err)
	}
	policy, err := NewExactPolicy(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// The constructor must not retain mutable caller-owned grant slices.
	snapshot.Grants[0].PrincipalID = "tampered"
	store := &inputCaptureStore{}
	svc := New(store, NewBearerResolver(policyTestAuthenticator{id}, policy, "fixture"))
	got, _, err := svc.AdmitWithInput(context.Background(), req, []byte("{}"))
	if err != nil || got.PrincipalID != "principal-alice" {
		t.Fatalf("mutable policy alias: %v", err)
	}
	policy.expiresAt = time.Now().Add(-time.Second)
	if _, _, err := svc.AdmitWithInput(context.Background(), req, []byte("{}")); !errors.Is(err, ErrPolicyUnavailable) || store.calls != 1 {
		t.Fatalf("expired snapshot accepted: %v", err)
	}
}
