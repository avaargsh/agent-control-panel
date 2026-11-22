package lease

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func verifyCommittedRevocation(ctx context.Context, pool *pgxpool.Pool, login string, oid uint32) error {
	var verified bool
	err := pool.QueryRow(ctx,
		"SELECT public.sandbox_verify_lease_login_revocation($1::name, $2::oid)",
		login, oid).Scan(&verified)
	if err != nil {
		return err
	}
	if !verified {
		return ErrConflict
	}
	return nil
}

// Revocation is NOT releasable merely because its SQL statement returned.
// An independent backend must observe a committed receipt, disabled LOGIN,
// zero role memberships, zero RLS bindings, and zero authenticated backends.
func TestLeaseRevocationVerificationRequiresCommittedState(t *testing.T) {
	owner := testRepository(t)
	ctx := context.Background()
	const login = "sandbox_lease_ci_verify_login"
	const password = "ci-only-verify"
	if _, err := owner.pool.Exec(ctx, "CREATE ROLE "+login+
		" LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, "GRANT acp_sandbox_lease_writer TO "+login); err != nil {
		t.Fatal(err)
	}
	var oid uint32
	if err := owner.pool.QueryRow(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1", login).Scan(&oid); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, `INSERT INTO public.sandbox_lease_db_principals
		(login_name,tenant_id) VALUES ($1,'tenant-a')`, login); err != nil {
		t.Fatal(err)
	}
	independent, err := pgxpool.New(ctx, os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer independent.Close()
	if err := verifyCommittedRevocation(ctx, independent, login, oid); err == nil {
		t.Fatal("DBA verification accepted an account with no revocation receipt")
	}
	tx, err := owner.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var terminated int
	if err := tx.QueryRow(ctx,
		"SELECT public.sandbox_revoke_lease_login($1::name,$2::oid)",
		login, oid).Scan(&terminated); err != nil {
		t.Fatal("owner-only revoke:", err)
	}
	// The verifier MUST use a separate pool/connection so an uncommitted
	// revocation cannot be mistaken for a completed post-commit fence.
	if err := verifyCommittedRevocation(ctx, independent, login, oid); err == nil {
		t.Fatal("external verification accepted an uncommitted revocation")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := verifyCommittedRevocation(ctx, independent, login, oid); err != nil {
		t.Fatalf("committed revocation failed independent verification: %v", err)
	}
	if err := verifyCommittedRevocation(ctx, independent, login, oid+1); err == nil {
		t.Fatal("verifier accepted a different role generation")
	}
	// A DBA re-opening a login after revocation must invalidate the proof.
	if _, err := owner.pool.Exec(ctx, "ALTER ROLE "+login+" LOGIN"); err != nil {
		t.Fatal(err)
	}
	if err := verifyCommittedRevocation(ctx, independent, login, oid); err == nil {
		t.Fatal("revoked login was re-enabled without invalidating verification")
	}
	if _, err := owner.pool.Exec(ctx, "ALTER ROLE "+login+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	// A DBA restoring group membership must also invalidate verification.
	if _, err := owner.pool.Exec(ctx, "GRANT acp_sandbox_lease_writer TO "+login); err != nil {
		t.Fatal(err)
	}
	if err := verifyCommittedRevocation(ctx, independent, login, oid); err == nil {
		t.Fatal("writer role was re-granted without invalidating verification")
	}
	if _, err := owner.pool.Exec(ctx, "REVOKE acp_sandbox_lease_writer FROM "+login); err != nil {
		t.Fatal(err)
	}
	// Re-enrolling the same OID is a new authorization and must invalidate
	// the old revocation result, even if the old receipt remains append-only.
	// The existing 0008 DBA enrollment trigger refuses a NOLOGIN
	// principal. A dangerous operator must first re-enable the account;
	// even if subsequently disabled, that restored tenant mapping invalidates
	// the former revocation proof.
	if _, err := owner.pool.Exec(ctx, "ALTER ROLE "+login+" LOGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, `INSERT INTO public.sandbox_lease_db_principals
		(login_name,tenant_id) VALUES ($1,'tenant-a')`, login); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, "ALTER ROLE "+login+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	if err := verifyCommittedRevocation(ctx, independent, login, oid); err == nil {
		t.Fatal("re-created tenant mapping did not invalidate revocation")
	}
	if _, err := owner.pool.Exec(ctx,
		"DELETE FROM public.sandbox_lease_db_principals WHERE login_name=$1", login); err != nil {
		t.Fatal(err)
	}
	if err := verifyCommittedRevocation(ctx, independent, login, oid); err != nil {
		t.Fatalf("valid operator state was not independently verifiable: %v", err)
	}

	// After a receipt has been committed, privileged operators can still
	// regrant rights unrelated to the two expected lease groups. A verifier
	// that inspects only Writer/Reader membership misses those leftovers.
	// Each negative check owns its setup/cleanup, so both must execute on RED.
	t.Run("unexpected_role_membership", func(t *testing.T) {
		const extraRole = "sandbox_lease_ci_unexpected_group"
		if _, err := owner.pool.Exec(ctx, "CREATE ROLE "+extraRole+" NOLOGIN"); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.pool.Exec(ctx, "GRANT "+extraRole+" TO "+login); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = owner.pool.Exec(context.Background(), "REVOKE "+extraRole+" FROM "+login)
		}()
		if err := verifyCommittedRevocation(ctx, independent, login, oid); err == nil {
			t.Fatal("revocation verifier accepted unexpected residual role membership")
		}
	})
	t.Run("direct_lease_table_privilege", func(t *testing.T) {
		if _, err := owner.pool.Exec(ctx,
			"GRANT SELECT ON TABLE public.sandbox_lease_intents TO "+login); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = owner.pool.Exec(context.Background(),
				"REVOKE SELECT ON TABLE public.sandbox_lease_intents FROM "+login)
		}()
		if err := verifyCommittedRevocation(ctx, independent, login, oid); err == nil {
			t.Fatal("revocation verifier accepted residual direct lease SELECT grant")
		}
	})
	t.Run("direct_lease_column_privilege", func(t *testing.T) {
		if _, err := owner.pool.Exec(ctx,
			"GRANT UPDATE (state) ON public.sandbox_lease_intents TO "+login); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = owner.pool.Exec(context.Background(),
				"REVOKE UPDATE (state) ON public.sandbox_lease_intents FROM "+login)
		}()
		if err := verifyCommittedRevocation(ctx, independent, login, oid); err == nil {
			t.Fatal("revocation verifier accepted residual direct lease column UPDATE grant")
		}
	})
	t.Run("direct_governance_receipt_privilege", func(t *testing.T) {
		if _, err := owner.pool.Exec(ctx,
			"GRANT SELECT ON TABLE public.sandbox_lease_login_revocations TO "+login); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = owner.pool.Exec(context.Background(),
				"REVOKE SELECT ON TABLE public.sandbox_lease_login_revocations FROM "+login)
		}()
		if err := verifyCommittedRevocation(ctx, independent, login, oid); err == nil {
			t.Fatal("revocation verifier accepted direct governance receipt SELECT grant")
		}
	})
}

// Test that a receipt alone is not proof. A live authenticated backend must
// block verification even when an owner stages every other state correctly.
// The owner-only direct receipt insertion is a NEGATIVE fixture, never an
// application or recommended operational code path.
func TestLeaseRevocationVerifierRejectsLiveAuthenticatedBackend(t *testing.T) {
	owner := testRepository(t)
	ctx := context.Background()
	const login = "sandbox_lease_ci_live_verify_login"
	const password = "ci-only-live-verify"
	if _, err := owner.pool.Exec(ctx, "CREATE ROLE "+login+
		" LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, "GRANT acp_sandbox_lease_reader TO "+login); err != nil {
		t.Fatal(err)
	}
	var oid uint32
	if err := owner.pool.QueryRow(ctx,
		"SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1", login).Scan(&oid); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, `INSERT INTO public.sandbox_lease_db_principals
		(login_name,tenant_id) VALUES ($1,'tenant-a')`, login); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = login
	cfg.ConnConfig.Password = password
	client, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	var pid uint32
	if err := conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	// Simulate an unsafe DBA process that writes a source-owned receipt
	// but forgets to terminate the already authenticated session.
	if _, err := owner.pool.Exec(ctx, "ALTER ROLE "+login+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, "REVOKE acp_sandbox_lease_reader FROM "+login); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx,
		"DELETE FROM public.sandbox_lease_db_principals WHERE login_name=$1", login); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, `INSERT INTO public.sandbox_lease_login_revocations
		(login_name,login_role_oid,tenant_id,terminated_sessions,revoked_by)
		VALUES ($1,$2::oid,'tenant-a',0,current_user::name)`, login, oid); err != nil {
		t.Fatal(err)
	}
	if err := verifyCommittedRevocation(ctx, owner.pool, login, oid); err == nil {
		t.Fatal("verifier accepted receipt while authenticated backend is still alive")
	}
	var stopped bool
	if err := owner.pool.QueryRow(ctx,
		"SELECT pg_terminate_backend($1::integer,2000)", pid).Scan(&stopped); err != nil || !stopped {
		t.Fatalf("could not stop disposable session: stopped=%t err=%v", stopped, err)
	}
	if err := verifyCommittedRevocation(ctx, owner.pool, login, oid); err != nil {
		t.Fatalf("verifier still rejected after the live session was terminated: %v", err)
	}
}
