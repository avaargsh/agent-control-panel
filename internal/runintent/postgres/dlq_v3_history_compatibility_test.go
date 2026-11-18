package postgres

import (
	"context"
	"errors"
	"testing"
)

// Two Draft branches once proposed incompatible v3 identities. An orphaned
// alternative journal must not be silently left beside a newly applied v3.
func TestDispositionV3RejectsUnversionedAlternativeJournal(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"DROP TABLE inbox_dlq_dispositions",
		"DROP FUNCTION reject_inbox_dlq_disposition_mutation()",
		"DELETE FROM schema_migrations WHERE version=3",
		"CREATE TABLE dlq_dispositions (source_sequence bigint PRIMARY KEY)",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("prepare incompatible v3 history: %v", err)
		}
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("unversioned alternative DLQ journal was silently accepted: %v", err)
	}
	var safe bool
	if err := pool.QueryRow(ctx, `SELECT
		to_regclass('inbox_dlq_dispositions') IS NULL
		AND NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=3)`).Scan(&safe); err != nil {
		t.Fatal(err)
	}
	if !safe {
		t.Fatal("failed migration left a fabricated canonical v3 relation or ledger entry")
	}
}

// A recorded v3 from the competing Draft must never be reinterpreted as the
// canonical SQL, even when version numbers match.
func TestDispositionV3RejectsAlternativeRecordedIdentity(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "UPDATE schema_migrations SET name='0003_dlq_dispositions.sql' WHERE version=3"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("alternate recorded v3 migration was silently adopted: %v", err)
	}
}
