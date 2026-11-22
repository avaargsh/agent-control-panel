package lease

import (
	"context"
	"errors"
	"fmt"
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
	// Only the owner/DBA can bind an authenticated LOGIN to a trusted tenant.
	// A caller-supplied tenant field or SET ROLE must never change this.
	if _, err := owner.pool.Exec(ctx, `INSERT INTO public.sandbox_lease_db_principals
		(login_name, tenant_id) VALUES ($1,'tenant-a'),($2,'tenant-a')`,
		writerLogin, readerLogin); err != nil {
		t.Fatal("DBA tenant binding:", err)
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
	// Two authenticated non-owner DB sessions must not cross tenant
	// boundaries even if a caller supplies another tenant_id directly. A
	// tenant-scoped WHERE parameter in Go is not database authorization.
	foreign := in
	foreign.TenantID = "tenant-b"
	foreign.LeaseIntentID = "foreign-lease-1"
	if _, created, err := owner.Create(ctx, foreign); err != nil || !created {
		t.Fatalf("owner fixture failed to create foreign tenant: created=%t err=%v", created, err)
	}
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"writer_foreign_read", func() error {
			_, err := New(writer).Get(ctx, foreign.TenantID, foreign.LeaseIntentID)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return fmt.Errorf("cross-tenant writer read result=%v, want NotFound", err)
		}},
		{"reader_foreign_read", func() error {
			_, err := New(reader).Get(ctx, foreign.TenantID, foreign.LeaseIntentID)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return fmt.Errorf("cross-tenant reader read result=%v, want NotFound", err)
		}},
		{"writer_foreign_create", func() error {
			bad := foreign
			bad.LeaseIntentID = "foreign-lease-new"
			_, created, err := New(writer).Create(ctx, bad)
			if err != nil && !created {
				return nil
			}
			return fmt.Errorf("writer inserted across tenant: created=%t err=%v", created, err)
		}},
		{"writer_foreign_cancel", func() error {
			_, err := New(writer).CancelBeforeProvision(ctx, foreign.TenantID, foreign.LeaseIntentID, 1)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return fmt.Errorf("writer cancelled across tenant: %v", err)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Prove RLS is not just a blanket deny for unknown tenants: a second
	// real LOGIN bound by the DBA to tenant-b must succeed on tenant-b, while
	// the very same principal cannot read or write tenant-a.
	const bLogin = "sandbox_lease_ci_tenant_b_login"
	const bPassword = "ci-only-sandbox-tenant-b"
	if _, err := owner.pool.Exec(ctx, "CREATE ROLE "+bLogin+
		" LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+bPassword+"'"); err != nil {
		t.Fatal("DBA test-only tenant-b LOGIN:", err)
	}
	if _, err := owner.pool.Exec(ctx, "GRANT acp_sandbox_lease_writer TO "+bLogin); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, `INSERT INTO public.sandbox_lease_db_principals
		(login_name,tenant_id) VALUES ($1,'tenant-b')`, bLogin); err != nil {
		t.Fatal("DBA bind tenant-b:", err)
	}
	writerB := connect(bLogin, bPassword)
	if got, err := New(writerB).Get(ctx, foreign.TenantID, foreign.LeaseIntentID); err != nil || got.Intent != foreign {
		t.Fatalf("authorized tenant-b account could not read own state: %+v %v", got, err)
	}
	if _, err := New(writerB).Get(ctx, in.TenantID, in.LeaseIntentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant-b accessed tenant-a: %v", err)
	}
	ownB := foreign
	ownB.LeaseIntentID = "tenant-b-new"
	if _, created, err := New(writerB).Create(ctx, ownB); err != nil || !created {
		t.Fatalf("tenant-b unable to create own intent: created=%v err=%v", created, err)
	}
	if got, err := New(writerB).CancelBeforeProvision(ctx, ownB.TenantID, ownB.LeaseIntentID, 1); err != nil || got.Generation != 2 {
		t.Fatalf("tenant-b unable to cancel own intent: %+v %v", got, err)
	}

	// A role grant by itself is NOT a tenant binding. An authenticated,
	// otherwise valid LOGIN without a DBA-owned mapping sees no rows and
	// cannot create even a syntactically valid lease intent.
	const unboundLogin = "sandbox_lease_ci_unbound_login"
	const unboundPassword = "ci-only-unbound-tenant"
	if _, err := owner.pool.Exec(ctx, "CREATE ROLE "+unboundLogin+
		" LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+unboundPassword+"'"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, "GRANT acp_sandbox_lease_writer TO "+unboundLogin); err != nil {
		t.Fatal(err)
	}
	unbound := connect(unboundLogin, unboundPassword)
	if _, err := New(unbound).Get(ctx, in.TenantID, in.LeaseIntentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unbound LOGIN read lease data: %v", err)
	}
	unboundInput := in
	unboundInput.LeaseIntentID = "unbound-should-not-write"
	if _, created, err := New(unbound).Create(ctx, unboundInput); err == nil || created {
		t.Fatalf("unbound LOGIN created lease: created=%v err=%v", created, err)
	}

	// Arbitrary session variables are caller-controlled and cannot change
	// the database's authenticated LOGIN -> Tenant binding.
	txGUC, err := writer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txGUC.Exec(ctx, "SET LOCAL app.tenant_id='tenant-b'"); err != nil {
		t.Fatal(err)
	}
	var foreignRows int
	if err := txGUC.QueryRow(ctx, `SELECT count(*) FROM public.sandbox_lease_intents
		WHERE tenant_id='tenant-b'`).Scan(&foreignRows); err != nil {
		t.Fatal(err)
	}
	_ = txGUC.Rollback(ctx)
	if foreignRows != 0 {
		t.Fatalf("caller-controlled session tenant GUC bypassed RLS: %d", foreignRows)
	}
	// INSERT and the three mutable UPDATE columns are intentionally granted
	// to the writer; PostgreSQL must still block malformed partial transactions
	// at COMMIT, not rely on a permission error at the statement boundary.
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{
			name: "writer_cannot_cancel_without_event",
			sql: `UPDATE public.sandbox_lease_intents
				SET state='CANCELLED_BEFORE_PROVISION', generation=2, updated_at=clock_timestamp()
				WHERE tenant_id='tenant-a' AND lease_intent_id='sandbox-intent-1'`,
		},
		{
			name: "writer_cannot_preseed_future_cancellation",
			sql: `INSERT INTO public.sandbox_lease_intent_events
				(tenant_id,lease_intent_id,generation,event_type,payload)
				SELECT tenant_id, lease_intent_id, 2,
				'sandbox.lease-intent.cancelled-before-provision',
				jsonb_build_object('run_id',run_id,'runtime_attempt_id',runtime_attempt_id,
				'request_digest',request_digest)
				FROM public.sandbox_lease_intents
				WHERE tenant_id='tenant-a' AND lease_intent_id='sandbox-intent-1'`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := writer.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, tc.sql); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatalf("test must reach COMMIT under limited writer privileges: %v", err)
			}
			if err = tx.Commit(ctx); err == nil {
				t.Fatal("limited writer committed a partial source-owned fact")
			}
			got, inspectErr := New(reader).Get(ctx, in.TenantID, in.LeaseIntentID)
			if inspectErr != nil || got.Generation != 1 || got.State != WaitingForPermit {
				t.Fatalf("rejected direct write changed durable lease state: %+v %v", got, inspectErr)
			}
		})
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
		{"read_dba_tenant_bindings", "SELECT count(*) FROM public.sandbox_lease_db_principals"},
		{"rewrite_dba_tenant_binding", "UPDATE public.sandbox_lease_db_principals SET tenant_id='tenant-b' WHERE login_name='sandbox_lease_ci_writer_login'"},
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
