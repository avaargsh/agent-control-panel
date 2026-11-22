package journal

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/internal/identity"
	"github.com/jackc/pgx/v5/pgconn"
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
		"0009_tenant_login_revoke_evict.sql",
		"0010_command_tenant_login_rls.sql",
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

	// Exercise the write path using a distinct independently authenticated
	// tenant-B LOGIN. The writer is not the table owner and can only INSERT
	// immutable PERMIT_UNAVAILABLE facts for its DBA-bound tenant.
	const writerLogin = "sandbox_ci_command_tenant_b"
	const writerPassword = "command-rls-b-writer-ci-only"
	defer func() {
		_, _ = owner.pool.Exec(context.Background(), "DROP OWNED BY "+writerLogin)
		_, _ = owner.pool.Exec(context.Background(), "DROP ROLE IF EXISTS "+writerLogin)
	}()
	for _, sql := range []string{
		"CREATE ROLE " + writerLogin + " LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + writerPassword + "'",
		"GRANT CONNECT ON DATABASE sandbox_journal_ci TO " + writerLogin,
		"GRANT acp_sandbox_command_writer TO " + writerLogin,
		"GRANT acp_sandbox_command_reader TO " + writerLogin,
	} {
		if _, err := owner.pool.Exec(ctx, sql); err != nil {
			t.Fatalf("create tenant-B command writer role: %v", err)
		}
	}
	if _, err := owner.pool.Exec(ctx, `INSERT INTO public.sandbox_lease_db_principals
		(login_name,tenant_id) VALUES ($1,$2)`, writerLogin, inB.TenantID); err != nil {
		t.Fatalf("DBA tenant-B command writer binding: %v", err)
	}
	writerCfg := cfg.Copy()
	writerCfg.ConnConfig.User, writerCfg.ConnConfig.Password = writerLogin, writerPassword
	writer, err := pgxpool.NewWithConfig(ctx, writerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if got, err := New(writer).Get(ctx, inB.TenantID, inB.SandboxUID, inB.CommandID); err != nil || got.Identity != inB {
		t.Fatalf("authorized tenant-B command+Outbox unreadable: %+v %v", got, err)
	}
	if _, err := New(writer).Get(ctx, inA.TenantID, inA.SandboxUID, inA.CommandID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant-B writer read tenant-A journal despite RLS: %v", err)
	}
	ownB := inB
	ownB.CommandID = "tenant-b-new-command"
	if got, created, err := New(writer).RecordPermitUnavailable(ctx, ownB); err != nil || !created || got.Identity != ownB {
		t.Fatalf("tenant-B writer cannot insert own immutable command: got=%+v created=%t err=%v", got, created, err)
	}
	if _, created, err := New(writer).RecordPermitUnavailable(ctx, ownB); err != nil || created {
		t.Fatalf("tenant-B idempotent retry failed: created=%t err=%v", created, err)
	}
	forgedA := inA
	forgedA.CommandID = "forged-a-command"
	if _, created, err := New(writer).RecordPermitUnavailable(ctx, forgedA); err == nil || created {
		t.Fatalf("tenant-B writer inserted foreign tenant-A command: created=%t err=%v", created, err)
	}
	// A client-controlled custom GUC must not substitute for session_user.
	tx, err := writer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL app.tenant_id='tenant-a'"); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_journal_commands WHERE tenant_id='tenant-a'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("spoofed app.tenant_id bypassed authenticated LOGIN boundary: count=%d err=%v", count, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// A group grant without the DBA's OID-pinned LOGIN -> tenant mapping
	// must not authorize either read or atomic INSERT+Outbox.
	const unboundLogin = "sandbox_ci_command_unbound"
	const unboundPassword = "command-rls-unbound-ci-only"
	defer func() {
		_, _ = owner.pool.Exec(context.Background(), "DROP OWNED BY "+unboundLogin)
		_, _ = owner.pool.Exec(context.Background(), "DROP ROLE IF EXISTS "+unboundLogin)
	}()
	for _, statement := range []string{
		"CREATE ROLE " + unboundLogin + " LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + unboundPassword + "'",
		"GRANT acp_sandbox_command_writer TO " + unboundLogin,
	} {
		if _, err := owner.pool.Exec(ctx, statement); err != nil {
			t.Fatalf("create unbound Command writer: %v", err)
		}
	}
	unboundCfg := cfg.Copy()
	unboundCfg.ConnConfig.User, unboundCfg.ConnConfig.Password = unboundLogin, unboundPassword
	unbound, err := pgxpool.NewWithConfig(ctx, unboundCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer unbound.Close()
	if _, err := New(unbound).Get(ctx, inA.TenantID, inA.SandboxUID, inA.CommandID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unbound Command group reader saw tenant-A facts: %v", err)
	}
	unboundAttempt := inB
	unboundAttempt.CommandID = "unbound-command-attempt"
	if _, created, err := New(unbound).RecordPermitUnavailable(ctx, unboundAttempt); err == nil || created {
		t.Fatalf("unbound Command writer minted a receipt: created=%t err=%v", created, err)
	}
	readonlyAttempt := inA
	readonlyAttempt.CommandID = "reader-forged-command"
	if _, created, err := New(reader).RecordPermitUnavailable(ctx, readonlyAttempt); err == nil || created {
		t.Fatalf("SELECT-only Command reader minted a receipt: created=%t err=%v", created, err)
	}

	// The upstream 0009 owner-controlled revoke primitive terminates actual
	// authenticated sessions, removes the OID-fenced mapping and sets NOLOGIN.
	// Its effect must fence a previously valid Command writer, not only leases.
	var writerOID uint32
	if err := owner.pool.QueryRow(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1", writerLogin).Scan(&writerOID); err != nil {
		t.Fatal(err)
	}
	// A revoked LOGIN must not retain any inherited Command capabilities.
	// NOLOGIN plus RLS is necessary, but stale memberships must also be
	// removed so future DBA re-enrolment cannot resurrect implicit grants.
	var commandWriterMember, commandReaderMember bool
	if err := owner.pool.QueryRow(ctx, `SELECT
		pg_catalog.pg_has_role($1::name,'acp_sandbox_command_writer'::name,'MEMBER'),
		pg_catalog.pg_has_role($1::name,'acp_sandbox_command_reader'::name,'MEMBER')`, writerLogin).
		Scan(&commandWriterMember, &commandReaderMember); err != nil {
		t.Fatal(err)
	}
	if !commandWriterMember || !commandReaderMember {
		t.Fatalf("test fixture must begin with both Command role grants, writer=%t reader=%t", commandWriterMember, commandReaderMember)
	}
	// A shared NOLOGIN delegation can retain an effective Command grant after
	// direct grants are revoked. The owner-only revoker must refuse to claim
	// successful eviction when that indirect membership cannot be removed.
	const nestedGroup = "sandbox_ci_command_nested_readers"
	for _, statement := range []string{
		"CREATE ROLE " + nestedGroup + " NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
		"GRANT acp_sandbox_command_reader TO " + nestedGroup,
		"GRANT " + nestedGroup + " TO " + writerLogin,
	} {
		if _, err := owner.pool.Exec(ctx, statement); err != nil {
			t.Fatalf("setup delegated Command role: %v", err)
		}
	}
	defer func() {
		_, _ = owner.pool.Exec(context.Background(), "REVOKE "+nestedGroup+" FROM "+writerLogin)
		_, _ = owner.pool.Exec(context.Background(), "REVOKE acp_sandbox_command_reader FROM "+nestedGroup)
		_, _ = owner.pool.Exec(context.Background(), "DROP ROLE IF EXISTS "+nestedGroup)
	}()
	var nestedAttempt int
	nestedErr := owner.pool.QueryRow(ctx,
		`SELECT public.sandbox_revoke_lease_login($1::name,$2::oid)`,
		writerLogin, writerOID).Scan(&nestedAttempt)
	var nestedPgErr *pgconn.PgError
	if !errors.As(nestedErr, &nestedPgErr) || nestedPgErr.Code != "23514" {
		t.Fatalf("nested Command membership must fail closed with SQLSTATE 23514, got %v", nestedErr)
	}
	var loginEnabled, stillBound, receiptMinted bool
	if err := owner.pool.QueryRow(ctx, `SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE oid=$1`, writerOID).Scan(&loginEnabled); err != nil {
		t.Fatal(err)
	}
	if err := owner.pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM public.sandbox_lease_db_principals
		WHERE login_name=$1 AND login_role_oid=$2)`, writerLogin, writerOID).Scan(&stillBound); err != nil {
		t.Fatal(err)
	}
	if err := owner.pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM public.sandbox_lease_login_revocations
		WHERE login_role_oid=$1)`, writerOID).Scan(&receiptMinted); err != nil {
		t.Fatal(err)
	}
	if !loginEnabled || !stillBound || receiptMinted {
		t.Fatalf("failed revocation claimed a partial success: login=%t bound=%t receipt=%t", loginEnabled, stillBound, receiptMinted)
	}
	for _, statement := range []string{
		"REVOKE " + nestedGroup + " FROM " + writerLogin,
		"REVOKE acp_sandbox_command_reader FROM " + nestedGroup,
		"DROP ROLE " + nestedGroup,
	} {
		if _, err := owner.pool.Exec(ctx, statement); err != nil {
			t.Fatalf("remove delegated grant before ordinary revocation: %v", err)
		}
	}
	// After the DBA removes the offending delegation, the original precise
	// revoke path must still succeed and preserve immutable receipts.
	var terminated int
	if err := owner.pool.QueryRow(ctx, `SELECT public.sandbox_revoke_lease_login($1::name,$2::oid)`, writerLogin, writerOID).Scan(&terminated); err != nil {
		t.Fatalf("source-owned exact LOGIN/OID revocation failed: %v", err)
	}
	if err := owner.pool.QueryRow(ctx, `SELECT
		pg_catalog.pg_has_role($1::name,'acp_sandbox_command_writer'::name,'MEMBER'),
		pg_catalog.pg_has_role($1::name,'acp_sandbox_command_reader'::name,'MEMBER')`, writerLogin).
		Scan(&commandWriterMember, &commandReaderMember); err != nil {
		t.Fatal(err)
	}
	if commandWriterMember || commandReaderMember {
		t.Fatalf("revocation retained dangerous Command role grants: writer=%t reader=%t", commandWriterMember, commandReaderMember)
	}
	if _, err := New(writer).Get(ctx, inB.TenantID, inB.SandboxUID, inB.CommandID); err == nil {
		t.Fatal("revoked Command writer continued reading tenant facts")
	}
	revokedAttempt := inB
	revokedAttempt.CommandID = "revoked-command-attempt"
	if _, created, err := New(writer).RecordPermitUnavailable(ctx, revokedAttempt); err == nil || created {
		t.Fatalf("revoked Command writer minted an original Outbox: created=%t err=%v", created, err)
	}
	if got, err := owner.Get(ctx, ownB.TenantID, ownB.SandboxUID, ownB.CommandID); err != nil || got.Identity != ownB {
		t.Fatalf("revocation damaged durable committed command history: got=%+v err=%v", got, err)
	}
}
