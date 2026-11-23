package agentd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This test requires a distinct PostgreSQL LOGIN. It must not pass through
// the owner pool used by the source writer or rely on SET ROLE as a substitute
// for an independently authenticated reader identity.
func newEvidenceReaderPool(t *testing.T, owner *pgxpool.Pool, tenantID string) *pgxpool.Pool {
	t.Helper()
	role := fmt.Sprintf("acp_agentd_reader_login_%d", time.Now().UnixNano())
	roleSQL := pgx.Identifier{role}.Sanitize()
	passwordBytes := make([]byte, 24)
	if _, err := rand.Read(passwordBytes); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(passwordBytes)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := owner.Exec(ctx, "CREATE ROLE "+roleSQL+" LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '"+password+"'"); err != nil {
		t.Fatalf("create isolated evidence reader LOGIN: %v", err)
	}
	if _, err := owner.Exec(ctx, "GRANT sandbox_agentd_evidence_reader TO "+roleSQL); err != nil {
		_, _ = owner.Exec(context.Background(), "DROP ROLE "+roleSQL)
		t.Fatalf("grant the dedicated tenant-scoped evidence reader role: %v", err)
	}
	tag, err := owner.Exec(ctx, `INSERT INTO public.sandbox_agentd_evidence_reader_tenants(login_role,login_oid,tenant_id)
		SELECT r.rolname,r.oid,$2 FROM pg_catalog.pg_roles r WHERE r.rolname=$1 AND r.rolcanlogin`, role, tenantID)
	if err != nil || tag.RowsAffected() != 1 {
		_, _ = owner.Exec(context.Background(), "REVOKE sandbox_agentd_evidence_reader FROM "+roleSQL)
		_, _ = owner.Exec(context.Background(), "DROP ROLE "+roleSQL)
		t.Fatalf("bind authenticated reader LOGIN and original role OID to one tenant: rows=%d err=%v", tag.RowsAffected(), err)
	}
	t.Cleanup(func() {
		if _, err := owner.Exec(context.Background(), "DELETE FROM public.sandbox_agentd_evidence_reader_tenants WHERE login_role=$1", role); err != nil {
			t.Errorf("remove evidence reader tenant mapping: %v", err)
		}
		if _, err := owner.Exec(context.Background(), "REVOKE sandbox_agentd_evidence_reader FROM "+roleSQL); err != nil {
			t.Errorf("revoke evidence reader membership: %v", err)
		}
		if _, err := owner.Exec(context.Background(), "DROP OWNED BY "+roleSQL); err != nil {
			t.Errorf("drop evidence reader owned objects: %v", err)
		}
		if _, err := owner.Exec(context.Background(), "DROP ROLE "+roleSQL); err != nil {
			t.Errorf("drop evidence reader LOGIN: %v", err)
		}
	})
	cfg, err := pgxpool.ParseConfig(os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = password
	cfg.MaxConns = 2
	reader, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect with separate evidence reader LOGIN: %v", err)
	}
	t.Cleanup(reader.Close)
	return reader
}

func TestEvidenceReaderLoginIsTenantScopedAndReadOnly(t *testing.T) {
	owner := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	seedAlreadyAuthorizedAttempt(t, owner, ref)
	other := ref
	other.TenantID = "agentd-tenant-b"
	other.RunID = "22222222-2222-4222-8222-222222222222"
	other.CommandID = "command-b"
	other.AttemptID = "attempt-b"
	other.ProviderCommandUID = "provider-command-b"
	seedAlreadyAuthorizedAttempt(t, owner, other)

	ownerTx, err := owner.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidenceReaderLogin(context.Background(), ownerTx, ref.TenantID); err == nil {
		_ = ownerTx.Rollback(context.Background())
		t.Fatal("owner connection was accepted as the least-privilege evidence reader")
	}
	_ = ownerTx.Rollback(context.Background())

	reader := newEvidenceReaderPool(t, owner, ref.TenantID)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatalf("begin reader snapshot: %v", err)
	}
	if err := verifyEvidenceReaderLogin(ctx, tx, ref.TenantID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("dedicated read-only login rejected: %v", err)
	}
	if err := verifyEvidenceReaderLogin(ctx, tx, other.TenantID); err == nil {
		_ = tx.Rollback(ctx)
		t.Fatal("one authenticated database LOGIN was accepted for a second tenant")
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", other.TenantID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("bind tenant scope in reader transaction: %v", err)
	}
	var own, foreign int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_agentd_attempts WHERE tenant_id=$1", ref.TenantID).Scan(&own); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("read own tenant attempt: %v", err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_agentd_attempts WHERE tenant_id=$1", other.TenantID).Scan(&foreign); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("probe foreign tenant attempt: %v", err)
	}
	if own != 1 || foreign != 0 {
		_ = tx.Rollback(ctx)
		t.Fatalf("reader RLS scope mismatch: own=%d foreign=%d", own, foreign)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit reader snapshot: %v", err)
	}

	writeTx, err := reader.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeTx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", ref.TenantID); err != nil {
		_ = writeTx.Rollback(ctx)
		t.Fatal(err)
	}
	_, err = writeTx.Exec(ctx, "UPDATE public.sandbox_agentd_attempts SET status=status WHERE tenant_id=$1", ref.TenantID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		_ = writeTx.Rollback(ctx)
		t.Fatalf("evidence reader could mutate source attempts: pgErr=%v err=%v", pgErr, err)
	}
	_ = writeTx.Rollback(ctx)
}

 
// A mutable PostgreSQL custom GUC cannot switch the tenant associated with
// the authenticated LOGIN. A revoked binding or mismatched role OID must also
// hide every source row, even when the connection remains open.
func TestEvidenceReaderGUCForgeryOIDMismatchAndRevocationFailClosed(t *testing.T) {
	owner := testDatabase(t)
	cmd, original := startOwnedTestProcess(t, "10")
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	seedAlreadyAuthorizedAttempt(t, owner, original)

	foreign := original
	foreign.TenantID = "agentd-tenant-b"
	foreign.RunID = "22222222-2222-4222-8222-222222222222"
	foreign.CommandID = "foreign-command"
	foreign.AttemptID = "foreign-attempt"
	foreign.ProviderCommandUID = "foreign-provider-command"
	seedAlreadyAuthorizedAttempt(t, owner, foreign)

	reader := newEvidenceReaderPool(t, owner, original.TenantID)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var login string
	if err := reader.QueryRow(ctx, "SELECT session_user").Scan(&login); err != nil || login == "" {
		t.Fatalf("reader identity unavailable: %q %v", login, err)
	}
	tx, err := reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil { t.Fatal(err) }
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", foreign.TenantID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	var own, leaked int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_agentd_attempts WHERE tenant_id=$1", original.TenantID).Scan(&own); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_agentd_attempts WHERE tenant_id=$1", foreign.TenantID).Scan(&leaked); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if own != 1 || leaked != 0 {
		_ = tx.Rollback(ctx)
		t.Fatalf("GUC changed source tenant scope: own=%d foreign=%d", own, leaked)
	}
	if err := tx.Commit(ctx); err != nil { t.Fatal(err) }

	// Simulate a stale role mapping after a LOGIN was recreated: the saved
	// name remains but its owner-maintained role OID no longer matches.
	tag, err := owner.Exec(ctx, `UPDATE public.sandbox_agentd_evidence_reader_tenants
		SET login_oid=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
		WHERE login_role=$1`, login)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("could not simulate stale role OID: rows=%d err=%v", tag.RowsAffected(), err)
	}
	checkNoReads := func(stage string) {
		t.Helper()
		var count int
		if err := reader.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_agentd_attempts WHERE tenant_id=$1", original.TenantID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s: original rows visible after binding lost: count=%d err=%v", stage, count, err)
		}
		txn, err := reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil { t.Fatal(err) }
		if err := verifyEvidenceReaderLogin(ctx, txn, original.TenantID); err == nil {
			_ = txn.Rollback(ctx)
			t.Fatalf("%s: untrusted binding accepted", stage)
		}
		_ = txn.Rollback(ctx)
	}
	checkNoReads("role OID mismatch")
	tag, err = owner.Exec(ctx, `UPDATE public.sandbox_agentd_evidence_reader_tenants b
		SET login_oid=r.oid FROM pg_catalog.pg_roles r
		WHERE b.login_role=r.rolname AND b.login_role=$1`, login)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("could not restore authenticated role OID: rows=%d err=%v", tag.RowsAffected(), err)
	}
	tag, err = owner.Exec(ctx, "DELETE FROM public.sandbox_agentd_evidence_reader_tenants WHERE login_role=$1", login)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("owner failed to revoke reader binding: rows=%d err=%v", tag.RowsAffected(), err)
	}
	checkNoReads("revoked binding")
}
