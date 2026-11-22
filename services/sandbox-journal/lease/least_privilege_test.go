package lease

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A real non-owner LOGIN connection (not SET ROLE on an owner connection) must
// retain the non-dispatch workflow and lack any schema/trigger authority.
// Passwords and LOGIN identities below are disposable CI-only fixtures.
func TestLeaseRuntimeDatabaseRolesDenyEscalationAndPreserveCAS(t *testing.T) {
	owner := testRepository(t)
	ctx := context.Background()
	const writerLogin = "sandbox_lease_ci_writer_login"
	const readerLogin = "sandbox_lease_ci_reader_login"
	const testWriterPassword = "ci-only-sandbox-lease-writer"
	const testReaderPassword = "ci-only-sandbox-lease-reader"
	for _, sql := range []string{
		"CREATE ROLE " + writerLogin + " LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + testWriterPassword + "'",
		"CREATE ROLE " + readerLogin + " LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + testReaderPassword + "'",
	} {
		if _, err := owner.pool.Exec(ctx, sql); err != nil {
			t.Fatalf("provision isolated test login: %v", err)
		}
	}
	// The owner-only role grant script must exist and be safely replayable.
	// Missing SQL or a changed existing role is a failed acceptance, not a skip.
	sql, err := os.ReadFile(filepath.Join("..", "migrations", "0004_lease_runtime_roles.sql"))
	if err != nil {
		t.Fatal("required Sandbox runtime role policy missing:", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := owner.pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply/replay owner-only runtime role grants (iteration %d): %v", i, err)
		}
	}
	if _, err := owner.pool.Exec(ctx, "GRANT acp_sandbox_lease_writer TO "+writerLogin); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, "GRANT acp_sandbox_lease_reader TO "+readerLogin); err != nil {
		t.Fatal(err)
	}
	connect := func(user, password string) *pgxpool.Pool {
		t.Helper()
		config, err := pgxpool.ParseConfig(os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		config.ConnConfig.User = user
		config.ConnConfig.Password = password
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatalf("open restricted PostgreSQL connection: %v", err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	writer := connect(writerLogin, testWriterPassword)
	reader := connect(readerLogin, testReaderPassword)
	in := sampleIntent()
	record, created, err := New(writer).Create(ctx, in)
	if err != nil || !created || record.Generation != 1 || record.State != WaitingForPermit {
		t.Fatalf("least privileged real LOGIN could not atomically create intent: created=%t state=%s err=%v", created, record.State, err)
	}
	again, created, err := New(writer).Create(ctx, in)
	if err != nil || created || again.Intent != in {
		t.Fatalf("least privileged writer idempotent replay: %t %v", created, err)
	}
	if _, err := New(reader).Get(ctx, in.TenantID, in.LeaseIntentID); err != nil {
		t.Fatalf("least privileged reader cannot inspect: %v", err)
	}
	for _, tc := range []struct{ name, sql string }{
		{"disable_update_trigger", "ALTER TABLE public.sandbox_lease_intent_events DISABLE TRIGGER sandbox_lease_outbox_no_update_delete"},
		{"disable_truncate_trigger", "ALTER TABLE public.sandbox_lease_intent_events DISABLE TRIGGER sandbox_lease_outbox_no_truncate"},
		{"rewrite_event", "UPDATE public.sandbox_lease_intent_events SET payload=payload"},
		{"delete_event", "DELETE FROM public.sandbox_lease_intent_events"},
		{"truncate_event", "TRUNCATE public.sandbox_lease_intent_events"},
		{"rewrite_run", "UPDATE public.sandbox_lease_intents SET run_id=run_id"},
		{"delete_intent", "DELETE FROM public.sandbox_lease_intents"},
		{"read_other_service_journal", "SELECT count(*) FROM public.sandbox_journal_commands"},
		{"create_table", "CREATE TABLE public.sandbox_lease_ci_escalation (id integer)"},
		{"escalate_to_owner", "SET ROLE sandbox_ci"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// PostgreSQL permission failures must not poison a connection used
			// by other checks; each denied SQL executes in its own transaction.
			tx, err := writer.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, tc.sql)
			_ = tx.Rollback(ctx)
			if err == nil {
				t.Fatalf("restricted writer performed forbidden SQL: %s", tc.sql)
			}
		})
	}
	if _, _, err := New(reader).Create(ctx, in); err == nil {
		t.Fatal("reader acquired write authority")
	}
	if _, err := New(reader).CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1); err == nil {
		t.Fatal("reader acquired cancel authority")
	}
	cancelled, err := New(writer).CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1)
	if err != nil || cancelled.Generation != 2 || cancelled.State != CancelledBeforeProvision {
		t.Fatalf("limited writer CAS failed: %+v %v", cancelled, err)
	}
	after, err := New(reader).Get(ctx, in.TenantID, in.LeaseIntentID)
	if err != nil || after.Generation != 2 || after.State != CancelledBeforeProvision {
		t.Fatalf("limited reader final state unavailable: %+v %v", after, err)
	}
	var actual string
	if err := writer.QueryRow(ctx, "SELECT current_user").Scan(&actual); err != nil || !strings.EqualFold(actual, writerLogin) {
		t.Fatalf("not actually using restricted LOGIN: %q %v", actual, err)
	}
}
