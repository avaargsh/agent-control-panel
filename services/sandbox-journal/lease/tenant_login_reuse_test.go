package lease

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A PostgreSQL LOGIN name can be reused after DROP ROLE. The new account
// must never inherit the deleted account's DBA-owned tenant authorization.
func TestLeaseTenantBindingRejectsDroppedAndRecreatedLogin(t *testing.T) {
	owner := testRepository(t)
	ctx := context.Background()
	const login = "sandbox_lease_ci_reused_login"
	const oldPassword = "ci-only-old-login"
	const newPassword = "ci-only-recreated-login"

	createLogin := func(password string) {
		t.Helper()
		if _, err := owner.pool.Exec(ctx, "CREATE ROLE "+login+
			" LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'"); err != nil {
			t.Fatal("create disposable LOGIN:", err)
		}
		if _, err := owner.pool.Exec(ctx, "GRANT acp_sandbox_lease_writer TO "+login); err != nil {
			t.Fatal("grant disposable writer:", err)
		}
	}
	connect := func(password string) *pgxpool.Pool {
		t.Helper()
		config, err := pgxpool.ParseConfig(os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		config.ConnConfig.User = login
		config.ConnConfig.Password = password
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		return pool
	}

	createLogin(oldPassword)
	var originalOID uint32
	if err := owner.pool.QueryRow(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1", login).Scan(&originalOID); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, `INSERT INTO public.sandbox_lease_db_principals
		(login_name, tenant_id) VALUES ($1, 'tenant-a')`, login); err != nil {
		t.Fatal("DBA tenant binding:", err)
	}
	original := connect(oldPassword)
	in := sampleIntent()
	in.LeaseIntentID = "lease-credential-reuse"
	if _, created, err := New(original).Create(ctx, in); err != nil || !created {
		t.Fatalf("original trusted LOGIN cannot create own lease: created=%t err=%v", created, err)
	}
	original.Close()
	if _, err := owner.pool.Exec(ctx, "REVOKE acp_sandbox_lease_writer FROM "+login); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.pool.Exec(ctx, "DROP ROLE "+login); err != nil {
		t.Fatal("drop old account, mapping should not silently transfer:", err)
	}
	createLogin(newPassword)
	var replacementOID uint32
	if err := owner.pool.QueryRow(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1", login).Scan(&replacementOID); err != nil {
		t.Fatal(err)
	}
	if originalOID == replacementOID {
		t.Fatal("test did not provision a distinct replacement role OID")
	}
	replacement := connect(newPassword)
	defer replacement.Close()

	if _, err := New(replacement).Get(ctx, in.TenantID, in.LeaseIntentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RECREATED login inherited deleted role tenant read authorization: %v", err)
	}
	forged := in
	forged.LeaseIntentID = "lease-recreated-should-be-denied"
	if _, created, err := New(replacement).Create(ctx, forged); err == nil || created {
		t.Fatalf("RECREATED login inherited deleted role tenant write authorization: created=%t err=%v", created, err)
	}
	if got, err := owner.Get(ctx, in.TenantID, in.LeaseIntentID); err != nil || got.Intent != in {
		t.Fatalf("revocation damaged original immutable source history: %+v %v", got, err)
	}
}
