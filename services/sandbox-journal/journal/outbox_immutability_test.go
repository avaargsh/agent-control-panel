package journal

import (
	"context"
	"testing"
)

// Ordinary writer SQL must never edit or erase a source-owned historical
// PERMIT_UNAVAILABLE command or its atomic Outbox fact. All cases run on the
// independent PostgreSQL 16 Sandbox database, not ACP's RunIntent database.
func TestJournalAndOutboxRejectOrdinaryMutation(t *testing.T) {
	for _, tc := range []struct {
		name string
		statement string
	}{
		{"outbox_noop_update", "UPDATE sandbox_journal_outbox SET payload=payload WHERE generation=1"},
		{"outbox_delete", "DELETE FROM sandbox_journal_outbox WHERE generation=1"},
		{"outbox_truncate", "TRUNCATE sandbox_journal_outbox"},
		{"command_noop_update", "UPDATE sandbox_journal_commands SET run_id=run_id WHERE generation=1"},
		{"command_truncate_cascade", "TRUNCATE sandbox_journal_commands CASCADE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := setup(t)
			ctx := context.Background()
			in := sample()
			if _, created, err := repo.RecordPermitUnavailable(ctx, in); err != nil || !created {
				t.Fatalf("initial committed command: created=%t err=%v", created, err)
			}
			if _, err := repo.pool.Exec(ctx, tc.statement); err == nil {
				t.Fatal("ordinary SQL was allowed to rewrite immutable Journal/Outbox")
			}
			if _, err := repo.Get(ctx, in.TenantID, in.SandboxUID, in.CommandID); err != nil {
				t.Fatalf("denied mutation changed committed source: %v", err)
			}
			if got := outboxCount(t, repo); got != 1 {
				t.Fatalf("denied mutation removed/duplicated Outbox: %d", got)
			}
		})
	}
}
