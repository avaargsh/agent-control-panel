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
func newEvidenceReaderPool(t *testing.T, owner *pgxpool.Pool) *pgxpool.Pool {
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
	t.Cleanup(func() {
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
	if err := verifyEvidenceReaderLogin(context.Background(), ownerTx); err == nil {
		_ = ownerTx.Rollback(context.Background())
		t.Fatal("owner connection was accepted as the least-privilege evidence reader")
	}
	_ = ownerTx.Rollback(context.Background())

	reader := newEvidenceReaderPool(t, owner)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatalf("begin reader snapshot: %v", err)
	}
	if err := verifyEvidenceReaderLogin(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("dedicated read-only login rejected: %v", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", ref.TenantID); err != nil {
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
