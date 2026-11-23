package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

// Guard has only the canonical authenticated tenant and Run selector.
// It cannot supply an arbitrary Intent ID, OAuth client or current policy.
func TestGuardRunAuthorityRequiresOriginalAdmissionAndLiveCatalog(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"INSERT INTO admission_tenants VALUES ('tenant-integration',true)",
		"INSERT INTO admission_projects VALUES ('tenant-integration','project-1',true,'policy-1')",
		"INSERT INTO admission_principals VALUES ('tenant-integration','https://identity.example.test','alice','principal-integration','subject-1',true)",
		"INSERT INTO admission_memberships VALUES ('tenant-integration','project-1','principal-integration','original-client','RUNNER',true), ('tenant-integration','project-1','principal-integration','replacement-client','RUNNER',true)",
		"INSERT INTO admission_releases VALUES ('tenant-integration','project-1','agent-1','release-1','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',true)",
		"INSERT INTO admission_sessions VALUES ('tenant-integration','project-1','session-1','agent-1','release-1','principal-integration',true)",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	intent := testIntent(981)
	raw := []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
	var err error
	intent.RequestDigest, err = runintent.ExecutionInputDigest(intent, raw)
	if err != nil {
		t.Fatal(err)
	}
	claims := CatalogClaims{Issuer: "https://identity.example.test", Subject: "alice", ClientID: "original-client", ExpiresAt: time.Now().Add(time.Hour)}
	binding, err := repo.ResolveCatalogAuthorization(ctx, intent, claims)
	if err != nil {
		t.Fatal(err)
	}
	intent.PrincipalSnapshot = binding.Snapshot
	if _, created, err := repo.CreateWithCatalog(ctx, intent, testEvent(intent, 1, 98101, eventCreated), raw, claims); err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	runID := "11111111-1111-4111-8111-111111111111"
	check := func(want error) {
		t.Helper()
		got, input, err := repo.GetGuardRunAuthority(ctx, intent.TenantID, runID)
		if want != nil {
			if !errors.Is(err, want) || len(input) != 0 {
				t.Fatalf("expected denial %v, got %v bytes %d", want, err, len(input))
			}
			return
		}
		if err != nil || got.Ref.RunID != runID || got.Ref.RunIntentID != intent.ID || got.Ref.RequestDigest != intent.RequestDigest || got.Snapshot != intent.PrincipalSnapshot || string(input) != string(raw) {
			t.Fatalf("authoritative accepted Run mismatch: %+v %s %v", got, input, err)
		}
	}
	check(ErrCatalogDenied) // pending Run is not authorized
	if _, err := pool.Exec(ctx, "UPDATE run_intents SET status='ACCEPTED',runtime_run_id=$2,workflow_id=$3,version=version+1 WHERE id=$1::uuid", intent.ID, runID, "agent-run/v1/"+runID); err != nil {
		t.Fatal(err)
	}
	check(nil)
	if _, _, err := repo.GetGuardRunAuthority(ctx, "another-tenant", runID); !errors.Is(err, ErrCatalogDenied) {
		t.Fatalf("cross-tenant Run resolved: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE admission_memberships SET enabled=false WHERE client_id='original-client'"); err != nil {
		t.Fatal(err)
	}
	check(ErrCatalogDenied) // replacement client may not launder original admission
	if _, err := pool.Exec(ctx, "UPDATE admission_memberships SET enabled=true WHERE client_id='original-client'"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE admission_releases SET enabled=false WHERE release_id='release-1'"); err != nil {
		t.Fatal(err)
	}
	check(ErrCatalogDenied)
	if _, err := pool.Exec(ctx, "UPDATE admission_releases SET enabled=true WHERE release_id='release-1'"); err != nil {
		t.Fatal(err)
	}
	check(nil)
	// The ACP schema currently does not globally enforce uniqueness of
	// runtime_run_id across distinct accepted Intents. Treat ambiguity as
	// unavailable: arbitrary QueryRow selection is a confused-deputy risk.
	second := testIntent(982)
	second.RequestDigest, err = runintent.ExecutionInputDigest(second, raw)
	if err != nil {
		t.Fatal(err)
	}
	secondBinding, err := repo.ResolveCatalogAuthorization(ctx, second, claims)
	if err != nil {
		t.Fatal(err)
	}
	second.PrincipalSnapshot = secondBinding.Snapshot
	if _, created, err := repo.CreateWithCatalog(ctx, second, testEvent(second, 1, 98201, eventCreated), raw, claims); err != nil || !created {
		t.Fatalf("second admission: %v %v", created, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE run_intents SET status='ACCEPTED',runtime_run_id=$2,workflow_id=$3,version=version+1 WHERE id=$1::uuid",
		second.ID, runID, "agent-run/v1/"+runID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.GetGuardRunAuthority(ctx, intent.TenantID, runID); !errors.Is(err, ErrCatalogUnavailable) {
		t.Fatalf("two accepted Intents selected an arbitrary capability authority: %v", err)
	}
}
