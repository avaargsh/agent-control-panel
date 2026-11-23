package journal

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// The upstream 0010 verification is Lease-scoped. After 0011 adds Command
// roles to the same source-owned revocation, a DBA must not interpret a
// successful Lease-only verification as proof that all Command object rights
// have also disappeared. These negatives run against real PostgreSQL ACLs.
func TestCommandRevocationProofRejectsResidualObjectAuthority(t *testing.T) {
	owner := setup(t)
	installCommandCommitMigrations(t, owner)
	ctx := context.Background()
	const login = "sandbox_ci_revoked_command_acl"
	const password = "ci-only-revoked-command-acl"
	defer func() {
		_, _ = owner.pool.Exec(context.Background(), "DROP OWNED BY "+login)
		_, _ = owner.pool.Exec(context.Background(), "DROP ROLE IF EXISTS "+login)
	}()
	for _, query := range []string{
		"CREATE ROLE " + login + " LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + password + "'",
		"GRANT acp_sandbox_command_writer TO " + login,
		"INSERT INTO public.sandbox_lease_db_principals (login_name,tenant_id) VALUES ('" + login + "','tenant-a')",
	} {
		if _, err := owner.pool.Exec(ctx, query); err != nil {
			t.Fatal("prepare authorized Command principal:", err)
		}
	}
	var oid uint32
	if err := owner.pool.QueryRow(ctx,
		"SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1", login).Scan(&oid); err != nil {
		t.Fatal(err)
	}
	var terminated int
	if err := owner.pool.QueryRow(ctx,
		"SELECT public.sandbox_revoke_lease_login($1::name,$2::oid)", login, oid).Scan(&terminated); err != nil {
		t.Fatal("revoke exact Command LOGIN/OID:", err)
	}
	verify := func(t *testing.T, shouldPass bool) {
		t.Helper()
		var valid bool
		err := owner.pool.QueryRow(ctx,
			"SELECT public.sandbox_verify_command_login_revocation($1::name,$2::oid)",
			login, oid).Scan(&valid)
		if shouldPass {
			if err != nil || !valid {
				t.Fatalf("clean committed Command revocation did not verify: valid=%t err=%v", valid, err)
			}
			return
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("residual Command authority must fail with SQLSTATE 23514, got %v", err)
		}
	}
	verify(t, true)

	t.Run("direct_command_table_select", func(t *testing.T) {
		if _, err := owner.pool.Exec(ctx, "GRANT SELECT ON public.sandbox_journal_commands TO "+login); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = owner.pool.Exec(context.Background(), "REVOKE SELECT ON public.sandbox_journal_commands FROM "+login)
		}()
		// Prove the precise gap: the original Lease-only verifier accepts
		// Command ACLs. The combined verifier MUST reject them.
		var leaseOnly bool
		if err := owner.pool.QueryRow(ctx,
			"SELECT public.sandbox_verify_lease_login_revocation($1::name,$2::oid)",
			login, oid).Scan(&leaseOnly); err != nil || !leaseOnly {
			t.Fatalf("source Lease-only baseline changed: valid=%t err=%v", leaseOnly, err)
		}
		verify(t, false)
		if _, err := owner.pool.Exec(ctx, "REVOKE SELECT ON public.sandbox_journal_commands FROM "+login); err != nil {
			t.Fatal(err)
		}
		verify(t, true)
	})
	t.Run("direct_command_outbox_column_update", func(t *testing.T) {
		if _, err := owner.pool.Exec(ctx, "GRANT UPDATE (payload) ON public.sandbox_journal_outbox TO "+login); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = owner.pool.Exec(context.Background(),
				"REVOKE UPDATE (payload) ON public.sandbox_journal_outbox FROM "+login)
		}()
		verify(t, false)
		if _, err := owner.pool.Exec(ctx, "REVOKE UPDATE (payload) ON public.sandbox_journal_outbox FROM "+login); err != nil {
			t.Fatal(err)
		}
		verify(t, true)
	})
	t.Run("direct_composite_verifier_execute", func(t *testing.T) {
		if _, err := owner.pool.Exec(ctx,
			"GRANT EXECUTE ON FUNCTION public.sandbox_verify_command_login_revocation(name,oid) TO "+login); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = owner.pool.Exec(context.Background(),
				"REVOKE EXECUTE ON FUNCTION public.sandbox_verify_command_login_revocation(name,oid) FROM "+login)
		}()
		verify(t, false)
		if _, err := owner.pool.Exec(ctx,
			"REVOKE EXECUTE ON FUNCTION public.sandbox_verify_command_login_revocation(name,oid) FROM "+login); err != nil {
			t.Fatal(err)
		}
		verify(t, true)
	})
}
