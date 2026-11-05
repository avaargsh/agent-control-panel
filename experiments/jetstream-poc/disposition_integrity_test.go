package jetstreampoc

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func journalIntegrityFixture() dispositionRecord {
	return dispositionRecord{
		stream:   "source_stream",
		consumer: "source_consumer",
		sequence: 42,
		hash:     strings.Repeat("a", 64),
		reason:   "EVENT_ID_CONFLICT",
		dlq:      "dlq_stream",
		subject:  "dlq.subject.42",
		evidence: []byte(`{"source_sequence":42}`),
	}
}

func TestDispositionJournalRejectsMutationAndStateRollback(t *testing.T) {
	_, pool := pocRepository(t)
	ctx := context.Background()
	journal := NewDispositionJournal(pool)
	record := journalIntegrityFixture()
	if _, _, err := journal.ensure(ctx, record); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"overwrite evidence", "UPDATE poc_dlq_dispositions SET evidence='tampered'::bytea"},
		{"overwrite identity", "UPDATE poc_dlq_dispositions SET reason='INBOX_QUARANTINED'"},
		{"delete pending disposition", "DELETE FROM poc_dlq_dispositions"},
		{"truncate journal", "TRUNCATE poc_dlq_dispositions"},
		{"mark confirmed before attempt", "UPDATE poc_dlq_dispositions SET published=true,published_at=clock_timestamp()"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, tc.sql); err == nil {
				t.Fatalf("disposition journal accepted forbidden mutation: %s", tc.sql)
			}
		})
	}
	if err := journal.confirm(ctx, record); !errors.Is(err, ErrDispositionConflict) {
		t.Fatalf("unattempted disposition confirmed: %v", err)
	}
	if err := journal.markPublishAttempt(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE poc_dlq_dispositions SET publish_started=false"); err == nil {
		t.Fatal("allowed resetting publish-attempt fence")
	}
	if err := journal.confirm(ctx, record); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"rollback confirmed state", "UPDATE poc_dlq_dispositions SET published=false,published_at=NULL"},
		{"forge confirmation timestamp", "UPDATE poc_dlq_dispositions SET published_at=clock_timestamp()+interval '1 day'"},
		{"erase confirmation", "DELETE FROM poc_dlq_dispositions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, tc.sql); err == nil {
				t.Fatalf("confirmed journal accepted forbidden mutation: %s", tc.sql)
			}
		})
	}
	// The journal API must continue to treat a completed retry as idempotent.
	if err := journal.confirm(ctx, record); err != nil {
		t.Fatalf("idempotent confirmation rejected: %v", err)
	}
}

func TestDispositionJournalMigrateDetectsGuardDrift(t *testing.T) {
	tests := []struct {
		name  string
		alter string
	}{
		{"dropped row trigger", "DROP TRIGGER poc_dlq_no_unsafe_update_delete ON poc_dlq_dispositions"},
		{"disabled row trigger", "ALTER TABLE poc_dlq_dispositions DISABLE TRIGGER poc_dlq_no_unsafe_update_delete"},
		{"row trigger conditionalized", `DROP TRIGGER poc_dlq_no_unsafe_update_delete ON poc_dlq_dispositions;
			CREATE TRIGGER poc_dlq_no_unsafe_update_delete BEFORE UPDATE OR DELETE ON poc_dlq_dispositions
			FOR EACH ROW WHEN (false) EXECUTE FUNCTION poc_reject_unsafe_disposition_mutation()`},
		{"row trigger only covers publish changes", `DROP TRIGGER poc_dlq_no_unsafe_update_delete ON poc_dlq_dispositions;
			CREATE TRIGGER poc_dlq_no_unsafe_update_delete BEFORE UPDATE OF published OR DELETE ON poc_dlq_dispositions
			FOR EACH ROW EXECUTE FUNCTION poc_reject_unsafe_disposition_mutation()`},
		{"changed guard function", `CREATE OR REPLACE FUNCTION poc_reject_unsafe_disposition_mutation()
			RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$`},
		{"dropped truncate trigger", "DROP TRIGGER poc_dlq_no_truncate ON poc_dlq_dispositions"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := pocRepository(t)
			ctx := context.Background()
			j := NewDispositionJournal(pool)
			if err := j.Migrate(ctx); err != nil {
				t.Fatalf("intact journal not accepted: %v", err)
			}
			if _, err := pool.Exec(ctx, tc.alter); err != nil {
				t.Fatalf("failed to inject guard drift: %v", err)
			}
			if err := j.Migrate(ctx); !errors.Is(err, ErrDispositionSchemaDrift) {
				t.Fatalf("migration accepted weakened/removed guard: %s; error=%v", tc.name, err)
			}
		})
	}
}
