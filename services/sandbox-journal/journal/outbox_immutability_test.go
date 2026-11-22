package journal

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Ordinary writer SQL must never edit or erase a source-owned historical
// PERMIT_UNAVAILABLE command or its atomic Outbox fact. All cases run on the
// independent PostgreSQL 16 Sandbox database, not ACP's RunIntent database.
func TestJournalAndOutboxRejectOrdinaryMutation(t *testing.T) {
	for _, tc := range []struct {
		name      string
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

// injectPreexistingJournalCorruption bypasses owner-only USER triggers inside
// one disposable test transaction. Production writers must NEVER disable
// append-only triggers or receive table-owner privileges.
func injectPreexistingJournalCorruption(t *testing.T, repo *Repository, sql string) {
	t.Helper()
	ctx := context.Background()
	tx, err := repo.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	for _, statement := range []string{
		"ALTER TABLE sandbox_journal_outbox DISABLE TRIGGER USER",
		sql,
		"ALTER TABLE sandbox_journal_outbox ENABLE TRIGGER USER",
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatal("test-only corruption injection:", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit test-only corruption:", err)
	}
}

func TestJournalOutboxMigrationRefusesInconsistentHistoricalFacts(t *testing.T) {
	for _, tc := range []struct {
		name string
		tamper string
	}{
		{"deleted_original", "DELETE FROM sandbox_journal_outbox WHERE generation=1"},
		{"forged_original_digest", `UPDATE sandbox_journal_outbox SET payload=jsonb_set(payload,'{request_digest}','"sha256:0000000000000000000000000000000000000000000000000000000000000000"'::jsonb)`},
		{"extra_sensitive_field", `UPDATE sandbox_journal_outbox SET payload=jsonb_set(payload,'{bearer_token}',to_jsonb('secret-not-allowed'::text))`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := setup(t)
			ctx := context.Background()
			if _, _, err := repo.RecordPermitUnavailable(ctx, sample()); err != nil {
				t.Fatal(err)
			}
			injectPreexistingJournalCorruption(t, repo, tc.tamper)
			migration, err := os.ReadFile(filepath.Join("..", "migrations", "0004_command_journal_outbox_immutable.sql"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repo.pool.Exec(ctx, string(migration)); err == nil {
				t.Fatal("migration installed append-only barrier over corrupted history")
			}
		})
	}
}

func TestJournalOutboxMigrationReplayPreservesValidHistoricalFacts(t *testing.T) {
	repo := setup(t)
	ctx := context.Background()
	in := sample()
	if _, created, err := repo.RecordPermitUnavailable(ctx, in); err != nil || !created {
		t.Fatalf("create receipt: created=%t err=%v", created, err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "migrations", "0004_command_journal_outbox_immutable.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.pool.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("replay migration rejected consistent history: %v", err)
	}
	if _, err := repo.Get(ctx, in.TenantID, in.SandboxUID, in.CommandID); err != nil {
		t.Fatalf("migration made immutable receipt unreadable: %v", err)
	}
	if got := outboxCount(t, repo); got != 1 {
		t.Fatalf("replayed migration rewrote Outbox: %d", got)
	}
	if _, err := repo.pool.Exec(ctx, "UPDATE sandbox_journal_outbox SET payload=payload"); err == nil {
		t.Fatal("migration replay removed append-only barrier")
	}
}
