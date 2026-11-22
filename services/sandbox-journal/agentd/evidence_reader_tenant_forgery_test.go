package agentd

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Regression for #116: a caller-controlled PostgreSQL custom setting is not
// authentication. Switching that setting must not switch the tenant that the
// SAME database LOGIN can read from the original AgentD source tables.
func TestEvidenceReaderCannotForgeTenantWithSessionGUC(t *testing.T) {
	owner := testDatabase(t)
	cmd, original := startOwnedTestProcess(t, "10")
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	seedAlreadyAuthorizedAttempt(t, owner, original)

	foreign := original
	foreign.TenantID = "agentd-tenant-b"
	foreign.RunID = "22222222-2222-4222-8222-222222222222"
	foreign.CommandID = "foreign-command"
	foreign.AttemptID = "foreign-attempt"
	foreign.ProviderCommandUID = "foreign-provider-command"
	seedAlreadyAuthorizedAttempt(t, owner, foreign)

	reader := newEvidenceReaderPool(t, owner, original.TenantID) // independent DB LOGIN / owner-managed tenant
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tx, err := reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var authenticatedLogin string
	if err := tx.QueryRow(ctx, "SELECT session_user").Scan(&authenticatedLogin); err != nil || authenticatedLogin == "" {
		t.Fatalf("cannot establish real session identity: login=%q err=%v", authenticatedLogin, err)
	}
	// Positive control: ordinary authorized tenant A must remain readable.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", original.TenantID); err != nil {
		t.Fatal(err)
	}
	var own int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_agentd_attempts WHERE tenant_id=$1", original.TenantID).Scan(&own); err != nil {
		t.Fatal(err)
	}
	if own != 1 {
		t.Fatalf("reader cannot read own tenant: count=%d", own)
	}

	// Attack: the identical authenticated LOGIN changes only the session GUC.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", foreign.TenantID); err != nil {
		t.Fatal(err)
	}
	var stillSameLogin string
	if err := tx.QueryRow(ctx, "SELECT session_user").Scan(&stillSameLogin); err != nil || stillSameLogin != authenticatedLogin {
		t.Fatalf("test unexpectedly switched the authenticated database LOGIN: %q -> %q (%v)",
			authenticatedLogin, stillSameLogin, err)
	}
	var foreignRows int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_agentd_attempts WHERE tenant_id=$1", foreign.TenantID).Scan(&foreignRows); err != nil {
		t.Fatal(err)
	}
	if foreignRows != 0 {
		t.Fatalf("P0 cross-tenant read: LOGIN %q controlled app.tenant_id and read %d foreign rows",
			authenticatedLogin, foreignRows)
	}
}

// Revoking the owner-maintained binding must deny the identical authenticated
// LOGIN, even if that LOGIN forges a formerly valid tenant custom setting.
func TestEvidenceReaderRevokedBindingDeniesSourceReads(t *testing.T) {
	owner := testDatabase(t)
	cmd, original := startOwnedTestProcess(t, "10")
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	seedAlreadyAuthorizedAttempt(t, owner, original)
	reader := newEvidenceReaderPool(t, owner, original.TenantID)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var login string
	if err := reader.QueryRow(ctx, "SELECT session_user").Scan(&login); err != nil || login == "" {
		t.Fatalf("cannot establish distinct reader LOGIN: %q %v", login, err)
	}
	deleted, err := owner.Exec(ctx,
		"DELETE FROM public.sandbox_agentd_reader_login_bindings WHERE login_name=$1", login)
	if err != nil || deleted.RowsAffected() != 1 {
		t.Fatalf("owner could not revoke reader tenant binding: rows=%d err=%v", deleted.RowsAffected(), err)
	}
	tx, err := reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", original.TenantID); err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidenceReaderLogin(ctx, tx); err == nil {
		t.Fatal("revoked authenticated reader binding was accepted as current authorization")
	}
	var count int
	if err := tx.QueryRow(ctx,
		"SELECT count(*) FROM public.sandbox_agentd_attempts WHERE tenant_id=$1",
		original.TenantID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("revoked login read %d original source rows: %v", count, err)
	}
}
