package lease

import (
	"context"
	"errors"
	"testing"
)

// injectPreexistingLeaseCorruption bypasses only test database OWNER triggers
// inside one transaction to model historical damage. Normal application
// UPDATE/DELETE/TRUNCATE must remain forbidden, as separately regression tested.
func injectPreexistingLeaseCorruption(t *testing.T, repo *Repository, sql string) {
	t.Helper()
	ctx := context.Background()
	tx, err := repo.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	for _, statement := range []string{
		"ALTER TABLE sandbox_lease_intent_events DISABLE TRIGGER USER",
		sql,
		"ALTER TABLE sandbox_lease_intent_events ENABLE TRIGGER USER",
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatal("test-only preexisting history injection:", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit test-only history injection:", err)
	}
}

// These cases use the independent PostgreSQL 16 Sandbox DB, not ACP's DB.
// A returned state must never be trusted if either original outbox fact is
// absent or no longer bound to the immutable intent.
func TestLeaseReplayAndGetRejectCorruptOriginalOutbox(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cancelled bool
		tamper    string
	}{
		{"missing_waiting_event", false, "DELETE FROM sandbox_lease_intent_events WHERE generation=1"},
		{"wrong_waiting_run", false, `UPDATE sandbox_lease_intent_events SET payload=jsonb_set(payload,'{run_id}','"forged-run"'::jsonb) WHERE generation=1`},
		{"extra_waiting_field", false, `UPDATE sandbox_lease_intent_events SET payload=jsonb_set(payload,'{token}',to_jsonb('private-token'::text)) WHERE generation=1`},
		{"missing_cancelled_event", true, "DELETE FROM sandbox_lease_intent_events WHERE generation=2"},
		{"changed_cancelled_digest", true, `UPDATE sandbox_lease_intent_events SET payload=jsonb_set(payload,'{request_digest}','"sha256:0000000000000000000000000000000000000000000000000000000000000000"'::jsonb) WHERE generation=2`},
		{"missing_original_after_cancel", true, "DELETE FROM sandbox_lease_intent_events WHERE generation=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := testRepository(t)
			ctx := context.Background()
			in := sampleIntent()
			if _, created, err := repo.Create(ctx, in); err != nil || !created {
				t.Fatalf("initial insert: created=%v err=%v", created, err)
			}
			if tc.cancelled {
				if _, err := repo.CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1); err != nil {
					t.Fatalf("cancel setup: %v", err)
				}
			}
			injectPreexistingLeaseCorruption(t, repo, tc.tamper)
			if _, created, err := repo.Create(ctx, in); created || !errors.Is(err, ErrCorrupt) {
				t.Fatalf("replay trusted disconnected outbox: created=%v err=%v", created, err)
			}
			if _, err := repo.Get(ctx, in.TenantID, in.LeaseIntentID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Get trusted disconnected outbox: %v", err)
			}
		})
	}
}

func TestLeaseCancelRefusesMissingOriginEventWithoutAdvancingGeneration(t *testing.T) {
	repo := testRepository(t)
	ctx := context.Background()
	in := sampleIntent()
	if _, created, err := repo.Create(ctx, in); err != nil || !created {
		t.Fatalf("create: %v, %v", created, err)
	}
	injectPreexistingLeaseCorruption(t, repo, "DELETE FROM sandbox_lease_intent_events WHERE generation=1")
	if _, err := repo.CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cancel advanced corrupt source history: %v", err)
	}
	var state string
	var generation int64
	if err := repo.pool.QueryRow(ctx, "SELECT state,generation FROM sandbox_lease_intents WHERE tenant_id=$1 AND lease_intent_id=$2", in.TenantID, in.LeaseIntentID).Scan(&state, &generation); err != nil {
		t.Fatal(err)
	}
	if state != WaitingForPermit || generation != 1 || events(t, repo) != 0 {
		t.Fatalf("corrupt-origin cancellation partially committed: %s/%d, events=%d", state, generation, events(t, repo))
	}
}
