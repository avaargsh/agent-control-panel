package lease

import (
	"context"
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
