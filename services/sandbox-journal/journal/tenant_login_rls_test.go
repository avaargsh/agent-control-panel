package journal

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantID in a WHERE clause is not authorization. Even if an API caller
// supplies a foreign tenant ID, an independently authenticated Sandbox
// PostgreSQL LOGIN must not see another tenant's pre-Permit command or its
// original Outbox receipt. This test initially demonstrates that plain
// SELECT grants are insufficient without owner-enforced Command RLS.
func TestCommandJournalReaderCannotReadOtherTenantWithOwnLogin(t *testing.T) {
	owner := setup(t)
	ctx := context.Background()
	inA := sample()
	inB := sample()
	inB.TenantID = "tenant-b"
	inB.RunID = "22222222-2222-4222-8222-222222222222"
	inB.RuntimeAttemptID = "runtime-attempt-b"
	inB.RequestDigest = "sha256:" + strings.Repeat("b", 64)
	for _, in := range []identity.Intent{inA, inB} {
		if _, created, err := owner.RecordPermitUnavailable(ctx, in); err != nil || !created {
			t.Fatalf("seed source-owned immutable command: created=%t err=%v", created, err)
		}
	}
	// Apply real owner-only migrations in order against the SAME committed
	// command and Outbox facts. This package runs before lease tests in CI,
	// so it cannot assume another test initialized the tenant registry.
	for _, name := range []string{
		"0002_lease_intents.sql",
		"0003_lease_outbox_immutable.sql",
		"0004_lease_runtime_roles.sql",
		"0006_lease_commit_integrity.sql",
		"0007_tenant_login_rls.sql",
		"0008_tenant_login_oid_fence.sql",
		"0009_command_tenant_login_rls.sql",
	} {
		sql, err := os.ReadFile("../migrations/" + name)
		if err != nil {
			t.Fatalf("read source-owned migration %s: %v", name, err)
		}
		if _, err := owner.pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply source-owned migration %s: %v", name, err)
		}
	}

	const login = "sandbox_ci_command_tenant_a"
	const password = "command-rls-disposable-ci-only"
	defer func() {
		_, _ = owner.pool.Exec(context.Background(), "DROP OWNED BY "+login)
		_, _ = owner.pool.Exec(context.Background(), "DROP ROLE IF EXISTS "+login)
	}()
	for _, sql := range []string{
		"CREATE ROLE " + login + " LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + password + "'",
		"GRANT CONNECT ON DATABASE sandbox_journal_ci TO " + login,
		"GRANT USAGE ON SCHEMA public TO " + login,
		"GRANT acp_sandbox_command_reader TO " + login,
	} {
		if _, err := owner.pool.Exec(ctx, sql); err != nil {
			t.Fatalf("setup isolated non-owner login: %v", err)
		}
	}
	if _, err := owner.pool.Exec(ctx, `INSERT INTO public.sandbox_lease_db_principals
		(login_name,tenant_id) VALUES ($1,$2)`, login, inA.TenantID); err != nil {
		t.Fatalf("DBA bind independent LOGIN to Command tenant: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User, cfg.ConnConfig.Password = login, password
	reader, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if got, err := New(reader).Get(ctx, inA.TenantID, inA.SandboxUID, inA.CommandID); err != nil || got.Identity != inA {
		t.Fatalf("own login cannot read own immutable command and receipt: %+v %v", got, err)
	}
	if _, err := New(reader).Get(ctx, inB.TenantID, inB.SandboxUID, inB.CommandID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant command+Outbox leaked under independent login: %v", err)
	}
	var count int
	if err := reader.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_journal_outbox WHERE tenant_id=$1", inB.TenantID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("foreign immutable Outbox readable without tenant authority: count=%d err=%v", count, err)
	}
}
