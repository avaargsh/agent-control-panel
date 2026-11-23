package lease

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Deployment must refuse to seal already-corrupt source facts. The test-only
// owner corruption injection is not available to restricted runtime roles.
func TestLeaseCommitMigrationRefusesCorruptHistoricalState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper string
	}{
		{
			name:   "missing_original_after_existing_state",
			tamper: "DELETE FROM sandbox_lease_intent_events WHERE generation=1",
		},
		{
			name: "premature_cancellation_after_existing_state",
			tamper: `INSERT INTO sandbox_lease_intent_events
				(tenant_id,lease_intent_id,generation,event_type,payload)
				SELECT tenant_id,lease_intent_id,2,'sandbox.lease-intent.cancelled-before-provision',
				jsonb_build_object('run_id',run_id,'runtime_attempt_id',runtime_attempt_id,
				'request_digest',request_digest)
				FROM sandbox_lease_intents WHERE generation=1`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := testRepository(t)
			ctx := context.Background()
			in := sampleIntent()
			if _, _, err := repo.Create(ctx, in); err != nil {
				t.Fatal(err)
			}
			injectPreexistingLeaseCorruption(t, repo, tc.tamper)
			migration, err := os.ReadFile(filepath.Join("..", "migrations", "0006_lease_commit_integrity.sql"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repo.pool.Exec(ctx, string(migration)); err == nil {
				t.Fatal("commit migration accepted corrupted preexisting history")
			}
		})
	}
}

func TestLeaseCommitMigrationReplaysWithoutWeakeningConstraints(t *testing.T) {
	repo := testRepository(t)
	ctx := context.Background()
	in := sampleIntent()
	if _, _, err := repo.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "migrations", "0006_lease_commit_integrity.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		if _, err := repo.pool.Exec(ctx, string(migration)); err != nil {
			t.Fatalf("safe migration replay %d failed: %v", n, err)
		}
	}
	if got, err := repo.Get(ctx, in.TenantID, in.LeaseIntentID); err != nil || got.Generation != 2 {
		t.Fatalf("valid history lost after replay: %+v %v", got, err)
	}
	if _, err := repo.pool.Exec(ctx, `UPDATE sandbox_lease_intents
		SET state='WAITING_FOR_PERMIT',generation=1
		WHERE tenant_id=$1 AND lease_intent_id=$2`, in.TenantID, in.LeaseIntentID); err == nil {
		t.Fatal("replayed migration allowed invalid state regression")
	}
}
