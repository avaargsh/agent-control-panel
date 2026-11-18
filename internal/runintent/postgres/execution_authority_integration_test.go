package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

func TestExecutionAuthorityRequiresOriginalCatalogClientAndAcceptedBinding(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"INSERT INTO admission_tenants VALUES ('tenant-integration',true)",
		"INSERT INTO admission_projects VALUES ('tenant-integration','project-1',true,'policy-1')",
		"INSERT INTO admission_principals VALUES ('tenant-integration','https://identity.example.test','alice','principal-integration','subject-1',true)",
		"INSERT INTO admission_memberships VALUES ('tenant-integration','project-1','principal-integration','client-1','RUNNER',true), ('tenant-integration','project-1','principal-integration','client-2','RUNNER',true)",
		"INSERT INTO admission_releases VALUES ('tenant-integration','project-1','agent-1','release-1','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',true)",
		"INSERT INTO admission_sessions VALUES ('tenant-integration','project-1','session-1','agent-1','release-1','principal-integration',true)",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	intent := testIntent(951)
	raw := []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
	var err error
	intent.RequestDigest, err = runintent.ExecutionInputDigest(intent, raw)
	if err != nil {
		t.Fatal(err)
	}
	claims := CatalogClaims{Issuer: "https://identity.example.test", Subject: "alice", ClientID: "client-1", ExpiresAt: time.Now().Add(time.Hour)}
	binding, err := repo.ResolveCatalogAuthorization(ctx, intent, claims)
	if err != nil {
		t.Fatal(err)
	}
	intent.PrincipalSnapshot = binding.Snapshot
	event := testEvent(intent, 1, 95101, eventCreated)
	if _, created, err := repo.CreateWithCatalog(ctx, intent, event, raw, claims); err != nil || !created {
		t.Fatalf("catalog create: %v", err)
	}
	ref := ExecutionAuthorityRef{TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest, RunID: "11111111-1111-4111-8111-111111111111"}
	if _, err := repo.GetExecutionAuthority(ctx, ref); !errors.Is(err, ErrCatalogDenied) {
		t.Fatalf("pending intent acquired continuation authority: %v", err)
	}
	// Same subject, same target and digest, different OAuth client. The
	// historical origin must not be replaced or silently replayed.
	other := claims
	other.ClientID = "client-2"
	if _, _, err := repo.CreateWithCatalog(ctx, intent, event, raw, other); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different client replay was not fenced: %v", err)
	}
	if _, _, err := repo.CreateWithInput(ctx, intent, event, raw); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("legacy replay downgraded catalog provenance: %v", err)
	}
	// These are isolated fixture state transitions, not proof of a live
	// Runtime receipt; the existing cross-service gate tests that boundary.
	if _, err := pool.Exec(ctx, "UPDATE run_intents SET status='ACCEPTED',runtime_run_id=$2,workflow_id=$3,version=version+1 WHERE id=$1::uuid", intent.ID, ref.RunID, "agent-run/v1/"+ref.RunID); err != nil {
		t.Fatal(err)
	}
	fresh, err := New(pool).GetExecutionAuthority(ctx, ref)
	if err != nil || fresh.Ref != ref || fresh.PrincipalID != intent.PrincipalID || fresh.Snapshot != intent.PrincipalSnapshot ||
		fresh.AgentID != intent.AgentID || fresh.ReleaseID != intent.ReleaseID || fresh.SessionID != intent.SessionID {
		t.Fatalf("accepted execution authority mismatch: %+v %v", fresh, err)
	}
	for _, changed := range []ExecutionAuthorityRef{
		{TenantID: "foreign", RunIntentID: ref.RunIntentID, RequestDigest: ref.RequestDigest, RunID: ref.RunID},
		{TenantID: ref.TenantID, RunIntentID: ref.RunIntentID, RequestDigest: ref.RequestDigest, RunID: "22222222-2222-4222-8222-222222222222"},
		{TenantID: ref.TenantID, RunIntentID: ref.RunIntentID, RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RunID: ref.RunID},
	} {
		if _, err := repo.GetExecutionAuthority(ctx, changed); !errors.Is(err, ErrCatalogDenied) {
			t.Fatalf("mismatched continuation binding allowed: %v", err)
		}
	}
	for _, update := range []string{
		"UPDATE run_intents SET admission_client_id='client-2'",
		"UPDATE run_intents SET admission_client_id=NULL,admission_issuer=NULL,admission_external_subject=NULL",
	} {
		if _, err := pool.Exec(ctx, update); err == nil {
			t.Fatal("immutable admission provenance mutated")
		}
	}
	for _, tc := range []struct {
		revoke  string
		restore string
	}{
		{"UPDATE admission_memberships SET enabled=false WHERE client_id='client-1'", "UPDATE admission_memberships SET enabled=true WHERE client_id='client-1'"},
		{"UPDATE admission_memberships SET role='VIEWER' WHERE client_id='client-1'", "UPDATE admission_memberships SET role='RUNNER' WHERE client_id='client-1'"},
		{"UPDATE admission_projects SET policy_revision='policy-2'", "UPDATE admission_projects SET policy_revision='policy-1'"},
		{"UPDATE admission_releases SET config_digest='sha256:'||repeat('c',64)", "UPDATE admission_releases SET config_digest='sha256:'||repeat('b',64)"},
		{"UPDATE admission_sessions SET enabled=false", "UPDATE admission_sessions SET enabled=true"},
		{"UPDATE admission_principals SET enabled=false", "UPDATE admission_principals SET enabled=true"},
	} {
		if _, err := pool.Exec(ctx, tc.revoke); err != nil {
			t.Fatal(err)
		}
		if _, err := New(pool).GetExecutionAuthority(ctx, ref); !errors.Is(err, ErrCatalogDenied) {
			t.Fatalf("revoked/stale original catalog origin allowed: %v", err)
		}
		if _, err := pool.Exec(ctx, tc.restore); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repo.GetExecutionAuthority(ctx, ref); err != nil {
		t.Fatal(err)
	}
	// Legacy records do not gain retroactive authority just because the
	// same catalog principal currently has a role.
	legacy := testIntent(952)
	legacy.IdempotencyKey = "legacy-origin"
	legacy.PrincipalSnapshot = binding.Snapshot
	legacy.RequestDigest, err = runintent.ExecutionInputDigest(legacy, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.CreateWithInput(ctx, legacy, testEvent(legacy, 1, 95201, eventCreated), raw); err != nil {
		t.Fatal(err)
	}
	legacyRun := "33333333-3333-4333-8333-333333333333"
	if _, err := pool.Exec(ctx, "UPDATE run_intents SET status='ACCEPTED',runtime_run_id=$2,workflow_id=$3,version=version+1 WHERE id=$1::uuid", legacy.ID, legacyRun, "agent-run/v1/"+legacyRun); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetExecutionAuthority(ctx, ExecutionAuthorityRef{TenantID: legacy.TenantID, RunIntentID: legacy.ID, RequestDigest: legacy.RequestDigest, RunID: legacyRun}); !errors.Is(err, ErrCatalogDenied) {
		t.Fatalf("legacy intent gained continuation authority: %v", err)
	}
	if _, _, err := repo.CreateWithCatalog(ctx, legacy, testEvent(legacy, 1, 95202, eventCreated), raw, claims); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("legacy provenance retroactively adopted: %v", err)
	}
}
