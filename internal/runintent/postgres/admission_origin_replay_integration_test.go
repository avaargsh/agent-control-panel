package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

// This regression intentionally uses only the pre-v12 public repository
// contract so it can also reproduce the bug on a pinned historical baseline.
func TestCatalogReplayCannotSwitchAuthenticatedClient(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"INSERT INTO admission_tenants VALUES ('tenant-integration',true)",
		"INSERT INTO admission_projects VALUES ('tenant-integration','project-1',true,'policy-1')",
		"INSERT INTO admission_principals VALUES ('tenant-integration','https://identity.example.test','alice','principal-integration','subject-1',true)",
		"INSERT INTO admission_memberships VALUES ('tenant-integration','project-1','principal-integration','client-1','RUNNER',true),('tenant-integration','project-1','principal-integration','client-2','RUNNER',true)",
		"INSERT INTO admission_releases VALUES ('tenant-integration','project-1','agent-1','release-1','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',true)",
		"INSERT INTO admission_sessions VALUES ('tenant-integration','project-1','session-1','agent-1','release-1','principal-integration',true)",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	intent := testIntent(953)
	raw := []byte(`{"task":"read-only"}`)
	var err error
	intent.RequestDigest, err = runintent.ExecutionInputDigest(intent, raw)
	if err != nil {
		t.Fatal(err)
	}
	first := CatalogClaims{Issuer: "https://identity.example.test", Subject: "alice", ClientID: "client-1", ExpiresAt: time.Now().Add(time.Hour)}
	binding, err := repo.ResolveCatalogAuthorization(ctx, intent, first)
	if err != nil {
		t.Fatal(err)
	}
	intent.PrincipalSnapshot = binding.Snapshot
	if _, created, err := repo.CreateWithCatalog(ctx, intent, testEvent(intent, 1, 95301, eventCreated), raw, first); err != nil || !created {
		t.Fatalf("initial real catalog admission failed: %v", err)
	}
	second := first
	second.ClientID = "client-2"
	if _, err := repo.ResolveCatalogAuthorization(ctx, intent, second); err != nil {
		t.Fatalf("second client must independently be a valid RUNNER: %v", err)
	}
	if _, created, err := repo.CreateWithCatalog(ctx, intent, testEvent(intent, 1, 95302, eventCreated), raw, second); err == nil && !created {
		t.Fatal("ADMISSION_ORIGIN_REPLAY_BYPASS: different client received original admitted RunIntent")
	} else if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected explicit idempotency conflict: %v", err)
	}
	if got := countOutbox(t, pool, intent.ID); got != 1 {
		t.Fatalf("client-conflict changed admission event count: %d", got)
	}
}
