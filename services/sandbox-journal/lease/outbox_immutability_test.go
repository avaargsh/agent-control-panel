package lease

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// These tests deliberately use the owner connection to prove that ordinary
// DML cannot silently rewrite an already committed lifecycle fact. Even an
// owner can disable triggers; least-privileged DB roles are still required.
func TestLeaseIntentOutboxRejectsOrdinaryMutation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cancelled bool
		sql       string
	}{
		{"waiting_update_same_bytes", false,
			"UPDATE sandbox_lease_intent_events SET payload=payload WHERE generation=1"},
		{"waiting_delete", false,
			"DELETE FROM sandbox_lease_intent_events WHERE generation=1"},
		{"waiting_truncate", false,
			"TRUNCATE sandbox_lease_intent_events"},
		{"cancelled_update_same_bytes", true,
			"UPDATE sandbox_lease_intent_events SET payload=payload WHERE generation=2"},
		{"cancelled_delete", true,
			"DELETE FROM sandbox_lease_intent_events WHERE generation=2"},
		{"cancelled_truncate", true,
			"TRUNCATE sandbox_lease_intent_events"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := testRepository(t)
			ctx := context.Background()
			in := sampleIntent()
			if _, created, err := repo.Create(ctx, in); err != nil || !created {
				t.Fatalf("create: created=%t err=%v", created, err)
			}
			wantEvents := 1
			if tc.cancelled {
				if _, err := repo.CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1); err != nil {
					t.Fatal(err)
				}
				wantEvents = 2
			}
			if _, err := repo.pool.Exec(ctx, tc.sql); err == nil {
				t.Fatal("ordinary SQL mutated immutable lease Outbox event")
			}
			if events(t, repo) != wantEvents {
				t.Fatalf("denied event mutation changed event count; got=%d want=%d", events(t, repo), wantEvents)
			}
			if _, err := repo.Get(ctx, in.TenantID, in.LeaseIntentID); err != nil {
				t.Fatalf("denied SQL caused history mismatch: %v", err)
			}
		})
	}
}

func TestLeaseOutboxMigrationRefusesInconsistentExistingHistory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper string
	}{
		{"deleted_original", "DELETE FROM sandbox_lease_intent_events WHERE generation=1"},
		{"changed_original_payload", `UPDATE sandbox_lease_intent_events SET payload=jsonb_set(payload,'{run_id}','"wrong-run"'::jsonb) WHERE generation=1`},
		{"unearned_cancellation_event", `INSERT INTO sandbox_lease_intent_events (tenant_id,lease_intent_id,generation,event_type,payload)
			SELECT tenant_id,lease_intent_id,2,'sandbox.lease-intent.cancelled-before-provision',
			jsonb_build_object('run_id',run_id,'runtime_attempt_id',runtime_attempt_id,'request_digest',request_digest)
			FROM sandbox_lease_intents WHERE generation=1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := testRepository(t)
			ctx := context.Background()
			in := sampleIntent()
			if _, _, err := repo.Create(ctx, in); err != nil {
				t.Fatal(err)
			}
			injectPreexistingLeaseCorruption(t, repo, tc.tamper)
			migration, err := os.ReadFile(filepath.Join("..", "migrations", "0003_lease_outbox_immutable.sql"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repo.pool.Exec(ctx, string(migration)); err == nil {
				t.Fatal("migration sealed corrupted existing lease history")
			}
		})
	}
}

func TestLeaseOutboxMigrationSafeToReplayOnValidHistory(t *testing.T) {
	repo := testRepository(t)
	ctx := context.Background()
	in := sampleIntent()
	if _, _, err := repo.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "migrations", "0003_lease_outbox_immutable.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.pool.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("idempotent additive migration rejected consistent history: %v", err)
	}
	if events(t, repo) != 2 {
		t.Fatal("idempotent migration changed historical event count")
	}
	if _, err := repo.Get(ctx, in.TenantID, in.LeaseIntentID); err != nil {
		t.Fatalf("valid history unreadable after migration replay: %v", err)
	}
	if _, err := repo.pool.Exec(ctx, "DELETE FROM sandbox_lease_intent_events WHERE generation=1"); err == nil {
		t.Fatal("replayed migration lost append-only trigger")
	}
}
