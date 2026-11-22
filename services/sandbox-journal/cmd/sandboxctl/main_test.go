package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/journal"
	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/lease"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOperatorOutputsShowDenialsAndNoSensitiveRequestDigests(t *testing.T) {
	leases, commands, query := exampleReaders()
	report, err := inspect(t.Context(), query, leases, commands)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"text", "json"} {
		var out bytes.Buffer
		if err := renderReport(&out, report, format); err != nil {
			t.Fatal(err)
		}
		body := out.String()
		if strings.Contains(body, strings.Repeat("a", 64)) || strings.Contains(body, strings.Repeat("b", 64)) {
			t.Fatalf("request digest leaked in %s output", format)
		}
		if format == "text" {
			for _, text := range []string{"UNATTESTED", "WAITING_FOR_PERMIT", "PERMIT_UNAVAILABLE", "Dispatch: DENIED", "Release: UNVERIFIED"} {
				if !strings.Contains(body, text) {
					t.Fatalf("missing safe hint %q in %s", text, body)
				}
			}
			continue
		}
		var decoded Report
		if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.NextAction != "HOLD" || decoded.CanDispatch || decoded.CanRetry ||
			decoded.CanDeclareSuccess || decoded.CanDeclareReleased {
			t.Fatalf("unsafe JSON report: %+v", decoded)
		}
	}
}

func TestOperatorRejectsUnsafeFlagsAndNeverPrintsDatabaseDSN(t *testing.T) {
	t.Setenv("SANDBOX_JOURNAL_READ_DSN", "postgres://a-secret-user:a-secret-password@invalid:5432/secret")
	bad := [][]string{
		nil, {"execute"}, {"inspect"}, {"inspect", "--tenant", "tenant-a"},
		{"inspect", "--tenant", "tenant-a", "--lease-intent", "bad id"},
		{"inspect", "--tenant", "tenant-a", "--lease-intent", "lease-1", "--format", "unsafe"},
		{"inspect", "--tenant", "tenant-a", "--lease-intent", "lease-1", "extra-argument"},
		{"inspect", "--tenant", "tenant-a", "--lease-intent", "lease-1", "--permit", "fake"},
	}
	for _, args := range bad {
		var stdout, stderr bytes.Buffer
		exit := run(args, &stdout, &stderr)
		if exit != 2 || stdout.Len() != 0 ||
			strings.Contains(stderr.String(), "a-secret-password") ||
			strings.Contains(stderr.String(), "a-secret-user") {
			t.Fatalf("unsafe or leaked input %v: exit %d stdout=%q stderr=%q", args, exit, stdout.String(), stderr.String())
		}
	}
	t.Setenv("SANDBOX_JOURNAL_READ_DSN", "")
	var stdout, stderr bytes.Buffer
	exit := run([]string{"inspect", "--tenant", "tenant-a", "--lease-intent", "lease-1"}, &stdout, &stderr)
	if exit != 3 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "READ_SOURCE_UNAVAILABLE") {
		t.Fatalf("missing DB was accepted: %d %q", exit, stderr.String())
	}
}

func TestSandboxctlRejectsPrivilegedDatabaseIdentityBeforeReading(t *testing.T) {
	dsn := os.Getenv("SANDBOX_JOURNAL_TEST_DSN")
	if dsn == "" {
		t.Skip("real independent Sandbox PostgreSQL role gate requires CI database")
	}
	// The CI migration owner is also a writable PostgreSQL principal.
	// A session default_transaction_read_only=on must NOT turn that
	// credential into acceptable read-only diagnostic authority.
	t.Setenv("SANDBOX_JOURNAL_READ_DSN", dsn)
	var stdout, stderr bytes.Buffer
	exit := run([]string{"inspect", "--tenant", "tenant-scope-a",
		"--lease-intent", "missing-lease"}, &stdout, &stderr)
	if exit != 3 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "READ_SOURCE_UNAVAILABLE") ||
		strings.Contains(stderr.String(), "UNVERIFIED") ||
		strings.Contains(stderr.String(), "sandbox-test-only") {
		t.Fatalf("writable DB credential was treated as read-only: exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}

func TestSandboxctlRealScopedReaderFixture(t *testing.T) {
	dsn := os.Getenv("SANDBOX_JOURNAL_READ_DSN")
	if dsn == "" {
		t.Skip("real SELECT-only sandbox reader DSN not configured")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("disposable SELECT-only DB role refused: %v", err)
	}
	leaseRow, err := lease.New(pool).Get(ctx, "sandboxctl-smoke", "lease-smoke-1")
	if err != nil {
		t.Fatalf("read seeded lease by SELECT-only role: %v", err)
	}
	commandRow, err := journal.New(pool).Get(ctx, "sandboxctl-smoke", "sandbox-smoke-1", "command-smoke-1")
	if err != nil {
		t.Fatalf("read seeded command by SELECT-only role: %v", err)
	}
	if leaseRow.Intent.RunID != commandRow.Identity.RunID ||
		leaseRow.Intent.RuntimeAttemptID != commandRow.Identity.RuntimeAttemptID {
		t.Fatal("seeded lease/command not bound to same Runtime identity")
	}
	_, err = inspect(ctx, Query{TenantID: "sandboxctl-smoke", LeaseIntentID: "lease-smoke-1",
		SandboxUID: "sandbox-smoke-1", CommandID: "command-smoke-1"}, lease.New(pool), journal.New(pool))
	if err != nil {
		t.Fatalf("valid SELECT-only fixture rejected by combined inspection: %v", err)
	}
}

// A PostgreSQL client may supply its own search_path. A writable credential
// with SELECT on same-named shadow tables must never pass the Sandbox reader
// preflight by making unqualified regclass lookups resolve to a false schema.
func TestSandboxctlRejectsShadowSchemaReadRoleBypass(t *testing.T) {
	dsn := os.Getenv("SANDBOX_JOURNAL_TEST_DSN")
	if dsn == "" {
		t.Skip("requires an isolated real PostgreSQL 16 Sandbox test database")
	}
	ctx := context.Background()
	owner, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	// The cmd package is run before the journal/lease packages in CI; install
	// the same source-owned base tables before setting up the real grant fixture.
	for _, name := range []string{"0001_command_journal.sql", "0002_lease_intents.sql"} {
		sql, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("install source-owned Sandbox schema %s: %v", name, err)
		}
	}
	const schema = "sandboxctl_shadow_schema"
	const username = "sandboxctl_shadow_login"
	statements := []string{
		"CREATE SCHEMA " + schema,
		"CREATE TABLE " + schema + ".sandbox_lease_intents (id integer)",
		"CREATE TABLE " + schema + ".sandbox_journal_commands (id integer)",
		"CREATE TABLE " + schema + ".sandbox_lease_intent_events (id integer)",
		"CREATE TABLE " + schema + ".sandbox_journal_outbox (id integer)",
		"CREATE ROLE " + username + " LOGIN PASSWORD 'sandboxctl-ci-shadow-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
		"GRANT CONNECT ON DATABASE sandbox_journal_ci TO " + username,
		"GRANT USAGE ON SCHEMA public," + schema + " TO " + username,
		"GRANT SELECT ON ALL TABLES IN SCHEMA " + schema + " TO " + username,
		"GRANT UPDATE ON public.sandbox_lease_intents TO " + username,
	}
	defer func() {
		_, _ = owner.Exec(context.Background(), "REVOKE UPDATE ON public.sandbox_lease_intents FROM "+username)
		_, _ = owner.Exec(context.Background(), "REVOKE ALL ON DATABASE sandbox_journal_ci FROM "+username)
		_, _ = owner.Exec(context.Background(), "REVOKE ALL ON SCHEMA public,"+schema+" FROM "+username)
		_, _ = owner.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		// Additional SELECT grants on the canonical public tables must be
		// revoked too, or the test leaves a reusable LOGIN in the CI DB.
		_, _ = owner.Exec(context.Background(), "DROP OWNED BY "+username)
		_, _ = owner.Exec(context.Background(), "DROP ROLE IF EXISTS "+username)
	}()
	for _, statement := range statements {
		if _, err := owner.Exec(ctx, statement); err != nil {
			t.Fatalf("prepare real shadow-schema role fixture: %v", err)
		}
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = username
	cfg.ConnConfig.Password = "sandboxctl-ci-shadow-only"
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	var effective bool
	if err := pool.QueryRow(ctx, "SELECT has_table_privilege(current_user, 'public.sandbox_lease_intents'::regclass, 'UPDATE')").Scan(&effective); err != nil || !effective {
		t.Fatalf("fixture is not a truly writable credential: effective=%t err=%v", effective, err)
	}
	if err := verifySandboxReadRole(ctx, pool); err == nil {
		t.Fatal("shadow search_path concealed UPDATE privileges on canonical public Sandbox tables")
	}

	// A role with no table DML may still advance a PostgreSQL Sequence.
	// Revoke the intentionally excessive table grant and establish a
	// positive SELECT-only baseline before granting any sequence right.
	for _, statement := range []string{
		"REVOKE UPDATE ON public.sandbox_lease_intents FROM " + username,
		"REVOKE SELECT ON ALL TABLES IN SCHEMA " + schema + " FROM " + username,
		"GRANT SELECT ON public.sandbox_lease_intents,public.sandbox_journal_commands,public.sandbox_lease_intent_events,public.sandbox_journal_outbox TO " + username,
	} {
		if _, err := owner.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("verified SELECT-only baseline rejected before sequence grant: %v", err)
	}
	const seq = schema + ".side_effect_probe"
	if _, err := owner.Exec(ctx, "CREATE SEQUENCE "+seq); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, "GRANT USAGE ON SEQUENCE "+seq+" TO "+username); err != nil {
		t.Fatal(err)
	}
	// Use a separate connection with the *same* independently authenticated
	// role but no client-side read-only hint, proving server ACL permits
	// nextval side effects; the CLI's hint is not privilege separation.
	probeCfg := cfg.Copy()
	probeCfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "off"
	probe, err := pgxpool.NewWithConfig(ctx, probeCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var advanced int64
	if err := probe.QueryRow(ctx, "SELECT nextval($1::regclass)", seq).Scan(&advanced); err != nil || advanced != 1 {
		t.Fatalf("real sequence ACL side effect was not possible: value=%d err=%v", advanced, err)
	}
	if err := verifySandboxReadRole(ctx, pool); err == nil {
		t.Fatal("writable sequence USAGE grant bypassed supposedly SELECT-only sandboxctl role gate")
	}
	if _, err := owner.Exec(ctx, "REVOKE USAGE ON SEQUENCE "+seq+" FROM "+username); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("sequence revocation did not restore SELECT-only reader: %v", err)
	}
	if err := probe.QueryRow(ctx, "SELECT nextval($1::regclass)", seq).Scan(&advanced); err == nil {
		t.Fatal("reader could still advance sequence after USAGE privilege revoked")
	}

	// PostgreSQL grants EXECUTE on newly created functions to PUBLIC.
	// SECURITY DEFINER runs under the owner's table privileges; a read-only
	// LOGIN with schema USAGE can therefore read data it has no table SELECT
	// for. This is a distinct privilege path from table and Sequence ACLs.
	const canaryTable = schema + ".owner_private_canary"
	const functionName = schema + ".read_owner_private"
	for _, statement := range []string{
		"CREATE TABLE " + canaryTable + " (payload text NOT NULL)",
		"INSERT INTO " + canaryTable + " VALUES ('sandbox-definer-canary')",
		"CREATE FUNCTION " + functionName + "() RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT payload FROM " + canaryTable + " LIMIT 1'",
	} {
		if _, err := owner.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	var canary string
	if err := probe.QueryRow(ctx, "SELECT "+functionName+"()").Scan(&canary); err != nil || canary != "sandbox-definer-canary" {
		t.Fatalf("fixture did not reproduce actual SECURITY DEFINER data escape: got=%q err=%v", canary, err)
	}
	if err := verifySandboxReadRole(ctx, pool); err == nil {
		t.Fatal("callable owner-privileged SECURITY DEFINER bypassed sandbox read-only role gate")
	}
	// An inaccessible routine should not block the good reader. Re-granting
	// directly must block again, despite revoking PUBLIC EXECUTE.
	if _, err := owner.Exec(ctx, "REVOKE EXECUTE ON FUNCTION "+functionName+"() FROM PUBLIC"); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("revoking PUBLIC SECURITY DEFINER EXECUTE did not restore reader: %v", err)
	}
	if _, err := owner.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+functionName+"() TO "+username); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err == nil {
		t.Fatal("direct SECURITY DEFINER EXECUTE grant bypassed sandbox reader role gate")
	}
	if _, err := owner.Exec(ctx, "REVOKE EXECUTE ON FUNCTION "+functionName+"() FROM "+username); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("revoking direct SECURITY DEFINER EXECUTE did not restore reader: %v", err)
	}
	// Migration 0006 uses a SECURITY DEFINER trigger function to check
	// original lease/Outbox integrity. PostgreSQL cannot invoke these
	// trigger-only routines with SELECT/CALL, despite default PUBLIC EXECUTE.
	// A diagnostic reader must not fail simply because that routine exists.
	const triggerName = schema + ".trigger_only_probe"
	if _, err := owner.Exec(ctx, "CREATE FUNCTION "+triggerName+
		"() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS 'BEGIN RETURN NEW; END'"); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("non-callable SECURITY DEFINER trigger blocked safe reader: %v", err)
	}

	// The four Sandbox-owned tables are the *entire* diagnostic reader's
	// allowed data surface. In particular, table ACLs for a foreign schema
	// can grant writable side effects without any CREATE, journal DML,
	// Sequence privilege or SECURITY DEFINER routine.
	const externalTable = schema + ".foreign_effect_probe"
	if _, err := owner.Exec(ctx, "CREATE TABLE "+externalTable+" (payload text NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, "GRANT INSERT ON "+externalTable+" TO "+username); err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, "INSERT INTO "+externalTable+" VALUES ('foreign-insert-verified')"); err != nil {
		t.Fatalf("actual independent LOGIN could not exercise foreign table INSERT: %v", err)
	}
	if err := verifySandboxReadRole(ctx, pool); err == nil {
		t.Fatal("foreign table INSERT privilege bypassed exact-four-table reader fence")
	}
	if _, err := owner.Exec(ctx, "REVOKE INSERT ON "+externalTable+" FROM "+username); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("revoking foreign INSERT did not restore dedicated read role: %v", err)
	}
	if _, err := owner.Exec(ctx, "GRANT SELECT ON "+externalTable+" TO "+username); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := probe.QueryRow(ctx, "SELECT payload FROM "+externalTable).Scan(&payload); err != nil || payload != "foreign-insert-verified" {
		t.Fatalf("actual foreign table SELECT not exercised: payload=%q err=%v", payload, err)
	}
	if err := verifySandboxReadRole(ctx, pool); err == nil {
		t.Fatal("unrelated foreign table SELECT privilege bypassed exact-four-table reader fence")
	}
	if _, err := owner.Exec(ctx, "REVOKE SELECT ON "+externalTable+" FROM "+username); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("revoking foreign SELECT did not restore dedicated read role: %v", err)
	}
	// Column grants can bypass a table-ACL-only allowlist. The test role
	// must be rejected even if it can read just one foreign column.
	if _, err := owner.Exec(ctx, "GRANT SELECT (payload) ON "+externalTable+" TO "+username); err != nil {
		t.Fatal(err)
	}
	if err := probe.QueryRow(ctx, "SELECT payload FROM "+externalTable).Scan(&payload); err != nil || payload != "foreign-insert-verified" {
		t.Fatalf("independent LOGIN did not exercise foreign column SELECT: payload=%q err=%v", payload, err)
	}
	if err := verifySandboxReadRole(ctx, pool); err == nil {
		t.Fatal("foreign column SELECT grant bypassed exact-four-table reader fence")
	}
	if _, err := owner.Exec(ctx, "REVOKE SELECT (payload) ON "+externalTable+" FROM "+username); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("revoking foreign column SELECT did not restore dedicated read role: %v", err)
	}

	// The login's effective ACLs alone are not enough. A NOINHERIT grant
	// with SET TRUE lets the same authenticated login switch to a helper
	// role, obtaining foreign-table INSERT even though the login's
	// ordinary current_user INSERT privilege remains false.
	const delegated = "sandboxctl_shadow_delegate"
	if _, err := owner.Exec(ctx, "CREATE ROLE "+delegated+
		" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = owner.Exec(context.Background(), "REVOKE "+delegated+" FROM "+username)
		_, _ = owner.Exec(context.Background(), "DROP OWNED BY "+delegated)
		_, _ = owner.Exec(context.Background(), "DROP ROLE IF EXISTS "+delegated)
	}()
	for _, grant := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + delegated,
		"GRANT INSERT ON " + externalTable + " TO " + delegated,
		"GRANT " + delegated + " TO " + username + " WITH INHERIT FALSE, SET TRUE",
	} {
		if _, err := owner.Exec(ctx, grant); err != nil {
			t.Fatalf("prepare delegated foreign writer: %v", err)
		}
	}
	var inherited bool
	if err := pool.QueryRow(ctx, "SELECT has_table_privilege(current_user, $1::regclass, 'INSERT')", externalTable).Scan(&inherited); err != nil || inherited {
		t.Fatalf("delegated permission was inherited or untestable: inherited=%t err=%v", inherited, err)
	}
	attacker, err := probe.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attacker.Exec(ctx, "SET ROLE "+delegated); err != nil {
		attacker.Release()
		t.Fatalf("actual login could not switch to delegated writer: %v", err)
	}
	_, effectErr := attacker.Exec(ctx, "INSERT INTO "+externalTable+" VALUES ('delegated-insert-verified')")
	_, resetErr := attacker.Exec(ctx, "RESET ROLE")
	attacker.Release()
	if effectErr != nil || resetErr != nil {
		t.Fatalf("actual delegated write failed: insert=%v reset=%v", effectErr, resetErr)
	}
	if err := verifySandboxReadRole(ctx, pool); err == nil {
		t.Fatal("SET ROLE to NOINHERIT foreign writer bypassed exact-four-table reader preflight")
	}
	// Membership remains, but removing the dangerous *group grant*
	// should restore this login's read-only status without removing it.
	if _, err := owner.Exec(ctx, "REVOKE INSERT ON "+externalTable+" FROM "+delegated); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("revoking delegated foreign INSERT did not restore reader: %v", err)
	}
	if _, err := owner.Exec(ctx, "GRANT USAGE ON SEQUENCE "+seq+" TO "+delegated); err != nil {
		t.Fatal(err)
	}
	writer, err := probe.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(ctx, "SET ROLE "+delegated); err != nil {
		writer.Release()
		t.Fatal(err)
	}
	sequenceErr := writer.QueryRow(ctx, "SELECT nextval($1::regclass)", seq).Scan(&advanced)
	_, resetErr = writer.Exec(ctx, "RESET ROLE")
	writer.Release()
	if sequenceErr != nil || resetErr != nil {
		t.Fatalf("delegated sequence mutation unavailable: nextval=%v reset=%v", sequenceErr, resetErr)
	}
	if err := verifySandboxReadRole(ctx, pool); err == nil {
		t.Fatal("NOINHERIT SET ROLE delegated sequence USAGE bypassed reader fence")
	}
	if _, err := owner.Exec(ctx, "REVOKE USAGE ON SEQUENCE "+seq+" FROM "+delegated); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("revoking delegated sequence privilege did not restore reader: %v", err)
	}

	if _, err := owner.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+functionName+"() TO "+delegated); err != nil {
		t.Fatal(err)
	}
	writer, err = probe.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(ctx, "SET ROLE "+delegated); err != nil {
		writer.Release()
		t.Fatal(err)
	}
	definerErr := writer.QueryRow(ctx, "SELECT "+functionName+"()").Scan(&canary)
	_, resetErr = writer.Exec(ctx, "RESET ROLE")
	writer.Release()
	if definerErr != nil || resetErr != nil || canary != "sandbox-definer-canary" {
		t.Fatalf("delegated SECURITY DEFINER escape unavailable: data=%q read=%v reset=%v", canary, definerErr, resetErr)
	}
	if err := verifySandboxReadRole(ctx, pool); err == nil {
		t.Fatal("NOINHERIT SET ROLE definer function bypassed reader fence")
	}
	if _, err := owner.Exec(ctx, "REVOKE EXECUTE ON FUNCTION "+functionName+"() FROM "+delegated); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("revoking delegated SECURITY DEFINER privilege did not restore reader: %v", err)
	}
	if _, err := owner.Exec(ctx, "REVOKE "+delegated+" FROM "+username); err != nil {
		t.Fatal(err)
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		t.Fatalf("revoking delegated SET ROLE membership did not restore reader: %v", err)
	}
}
