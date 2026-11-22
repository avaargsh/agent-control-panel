package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
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
		_, _ = owner.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
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
}
