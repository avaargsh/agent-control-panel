package lease

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Revoke through the owner-only, exact-OID operation. A mere DELETE of
// the mapping is not enough to fence an existing REPEATABLE READ snapshot.
func revokeLeasePrincipalForTest(ctx context.Context, owner *Repository, login string, roleOID uint32) error {
	var terminated int
	err := owner.pool.QueryRow(ctx,
		"SELECT public.sandbox_revoke_lease_login($1::name,$2::oid)",
		login, roleOID).Scan(&terminated)
	if err != nil {
		return err
	}
	if terminated < 1 {
		return fmt.Errorf("revocation did not evict the active tenant session: %d", terminated)
	}
	return nil
}

func TestLeaseRevocationEvictsExistingRepeatableReadSession(t *testing.T) {
	owner := testRepository(t)
	ctx := context.Background()
	const login = "sandbox_lease_ci_revoke_login"
	const password = "ci-only-revocation-test"
	_, err := owner.pool.Exec(ctx, "CREATE ROLE "+login+
		" LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owner.pool.Exec(ctx, "GRANT acp_sandbox_lease_writer TO "+login); err != nil {
		t.Fatal(err)
	}
	var roleOID uint32
	if err = owner.pool.QueryRow(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1", login).Scan(&roleOID); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.pool.Exec(ctx, `INSERT INTO public.sandbox_lease_db_principals
		(login_name,tenant_id) VALUES ($1,'tenant-a')`, login); err != nil {
		t.Fatal(err)
	}
	in := sampleIntent()
	in.LeaseIntentID = "revoke-active-tx"
	if _, created, err := owner.Create(ctx, in); err != nil || !created {
		t.Fatalf("owner fixture: created=%t err=%v", created, err)
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = login
	cfg.ConnConfig.Password = password
	active, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	tx, err := active.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	readCount := func() (int, error) {
		var count int
		err := tx.QueryRow(ctx, `SELECT count(*) FROM public.sandbox_lease_intents
			WHERE tenant_id='tenant-a' AND lease_intent_id='revoke-active-tx'`).Scan(&count)
		return count, err
	}
	if n, err := readCount(); err != nil || n != 1 {
		t.Fatalf("missing original active snapshot: rows=%d err=%v", n, err)
	}
	// The operator must supply the exact authenticated role generation.
	// An incorrect OID must not evict a legitimate tenant session.
	var ignored int
	if err := owner.pool.QueryRow(ctx,
		"SELECT public.sandbox_revoke_lease_login($1::name,$2::oid)",
		login, roleOID+1).Scan(&ignored); err == nil {
		t.Fatal("stale role generation was allowed to revoke a live principal")
	}
	if n, err := readCount(); err != nil || n != 1 {
		t.Fatalf("stale-OID revoke disrupted valid session: rows=%d err=%v", n, err)
	}
	if err := revokeLeasePrincipalForTest(ctx, owner, login, roleOID); err != nil {
		t.Fatal("DBA revocation failed:", err)
	}
	// With security-sensitive RLS, deleting an MVCC row is not enough: a
	// transaction that already took a REPEATABLE READ snapshot can still
	// observe its historical authorization. Revoke must evict that backend.
	if n, err := readCount(); err == nil {
		t.Fatalf("revoked active transaction still sees %d rows; session was not fenced", n)
	}
	var bound int
	if err := owner.pool.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_lease_db_principals WHERE login_name=$1", login).Scan(&bound); err != nil || bound != 0 {
		t.Fatalf("revocation kept DBA tenant mapping: count=%d err=%v", bound, err)
	}
	var sessions int
	if err := owner.pool.QueryRow(ctx, "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename=$1", login).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("revoked LOGIN retains %d authenticated PostgreSQL sessions", sessions)
	}
	if err := active.Ping(ctx); err == nil {
		t.Fatal(fmt.Sprintf("revoked LOGIN %s retained new database connectivity", login))
	}
	var savedOID uint32
	var savedTenant, revokedBy string
	var terminated int
	err = owner.pool.QueryRow(ctx, `SELECT login_role_oid, tenant_id, terminated_sessions, revoked_by
		FROM public.sandbox_lease_login_revocations WHERE login_name=$1`, login).
		Scan(&savedOID, &savedTenant, &terminated, &revokedBy)
	if err != nil || savedOID != roleOID || savedTenant != "tenant-a" || terminated < 1 || revokedBy == "" {
		t.Fatalf("source revocation fact invalid: oid=%d tenant=%s sessions=%d operator=%s err=%v",
			savedOID, savedTenant, terminated, revokedBy, err)
	}
	if err := owner.pool.QueryRow(ctx,
		"SELECT public.sandbox_revoke_lease_login($1::name,$2::oid)",
		login, roleOID).Scan(&ignored); err == nil {
		t.Fatal("repeat revocation succeeded without an active principal binding")
	}
	var facts int
	if err := owner.pool.QueryRow(ctx, `SELECT count(*)
		FROM public.sandbox_lease_login_revocations WHERE login_role_oid=$1::oid`,
		roleOID).Scan(&facts); err != nil || facts != 1 {
		t.Fatalf("stale retry altered revocation history: facts=%d err=%v", facts, err)
	}
	for _, statement := range []string{
		"UPDATE public.sandbox_lease_login_revocations SET tenant_id=tenant_id",
		"DELETE FROM public.sandbox_lease_login_revocations",
		"TRUNCATE public.sandbox_lease_login_revocations",
	} {
		if _, err := owner.pool.Exec(ctx, statement); err == nil {
			t.Fatalf("ordinary SQL modified source-owned revocation fact: %s", statement)
		}
	}
}
