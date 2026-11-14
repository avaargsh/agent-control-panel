package jetstreampoc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// This is an isolated PostgreSQL ACL test, NOT a production role installer.
// A superuser-owned disposable schema grants the worker only SELECT, INSERT
// and UPDATE on settlement state columns. It never grants owner/DDL,
// DELETE, TRUNCATE or evidence/identity updates.
func TestDispositionJournalRestrictedDatabaseRole(t *testing.T) {
	_, pool := pocRepository(t)
	ctx := context.Background()
	schema := pool.Config().ConnConfig.RuntimeParams["search_path"]
	role := "poc_journal_worker_" + strconv.FormatInt(time.Now().UnixNano(), 10)

	if _, err := pool.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatalf("create isolated test role: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DROP OWNED BY "+role); err != nil {
			t.Errorf("revoke role-owned test grants: %v", err)
			return
		}
		if _, err := pool.Exec(context.Background(), "DROP ROLE "+role); err != nil {
			t.Errorf("remove isolated test role: %v", err)
		}
	})
	for _, statement := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT SELECT, INSERT ON poc_dlq_dispositions TO " + role,
		"GRANT UPDATE (publish_started,published,published_at) ON poc_dlq_dispositions TO " + role,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("configure isolated role: %v", err)
		}
	}

	execAsWorker := func(sql string) error {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sql); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	receipt := journalIntegrityFixture()
	insert := fmt.Sprintf(
		"INSERT INTO poc_dlq_dispositions(source_stream,source_consumer,source_sequence,delivery_hash,reason,dlq_stream,dlq_subject,evidence) "+
			"VALUES ('%s','%s',%d,'%s','%s','%s','%s','\\x7b7d'::bytea)",
		receipt.stream, receipt.consumer, receipt.sequence, receipt.hash, receipt.reason, receipt.dlq, receipt.subject)
	if err := execAsWorker(insert); err != nil {
		t.Fatalf("least-privilege worker cannot insert durable disposition: %v", err)
	}
	if err := execAsWorker("UPDATE poc_dlq_dispositions SET publish_started=true"); err != nil {
		t.Fatalf("worker cannot mark durable publish attempt: %v", err)
	}
	if err := execAsWorker("UPDATE poc_dlq_dispositions SET published=true,published_at=clock_timestamp()"); err != nil {
		t.Fatalf("worker cannot mark confirmed disposition: %v", err)
	}

	for _, tc := range []struct {
		name     string
		sql      string
		wantCode string
	}{
		{"tamper evidence", "UPDATE poc_dlq_dispositions SET evidence='changed'::bytea", "42501"},
		{"tamper identity", "UPDATE poc_dlq_dispositions SET reason='INBOX_QUARANTINED'", "42501"},
		{"delete evidence", "DELETE FROM poc_dlq_dispositions", "42501"},
		{"truncate evidence", "TRUNCATE poc_dlq_dispositions", "42501"},
		{"change journal DDL", "ALTER TABLE poc_dlq_dispositions DROP CONSTRAINT poc_dlq_requires_attempt", "42501"},
		{"rollback confirmed state", "UPDATE poc_dlq_dispositions SET published=false,published_at=NULL", "P0001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := execAsWorker(tc.sql)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != tc.wantCode {
				t.Fatalf("worker privilege/trigger guard did not reject %q: %v (want SQLSTATE %s)", tc.name, err, tc.wantCode)
			}
		})
	}
}
