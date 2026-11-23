package agentd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A new permissive PUBLIC policy is OR-ed with the three expected
// tenant-scoped SELECT policies by PostgreSQL. Presence of those three
// policies alone is not evidence that RLS still isolates the reader.
func TestEvidenceReaderRejectsAdditionalPermissivePublicPolicy(t *testing.T) {
	owner := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	foreign := ref
	foreign.TenantID = "agentd-tenant-b"
	foreign.RunID = "22222222-2222-4222-8222-222222222222"
	foreign.CommandID = "foreign-policy-command"
	foreign.AttemptID = "foreign-policy-attempt"
	foreign.ProviderCommandUID = "foreign-policy-provider"
	seedAlreadyAuthorizedAttempt(t, owner, foreign)

	reader := newEvidenceReaderPool(t, owner, ref.TenantID)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	countForeign := func() int {
		t.Helper()
		var n int
		if err := reader.QueryRow(ctx,
			"SELECT count(*) FROM public.sandbox_agentd_attempts WHERE tenant_id=$1",
			foreign.TenantID).Scan(&n); err != nil {
			t.Fatalf("read foreign tenant count: %v", err)
		}
		return n
	}
	if n := countForeign(); n != 0 {
		t.Fatalf("baseline tenant RLS leak: foreign=%d", n)
	}
	tx, err := reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidenceReaderLogin(ctx, tx, ref.TenantID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("baseline valid evidence reader rejected: %v", err)
	}
	_ = tx.Rollback(ctx)

	const policy = "agentd_unsafe_extra_public_select"
	if _, err := owner.Exec(ctx, "CREATE POLICY "+policy+
		" ON public.sandbox_agentd_attempts FOR SELECT TO PUBLIC USING (true)"); err != nil {
		t.Fatalf("install additive overbroad policy: %v", err)
	}
	t.Cleanup(func() {
		if _, err := owner.Exec(context.Background(), "DROP POLICY IF EXISTS "+policy+
			" ON public.sandbox_agentd_attempts"); err != nil {
			t.Errorf("restore original source RLS policies: %v", err)
		}
	})
	if n := countForeign(); n != 1 {
		t.Fatalf("test did not reproduce real PostgreSQL RLS policy bypass: foreign=%d", n)
	}

	tx, err = reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidenceReaderLogin(ctx, tx, ref.TenantID); !errors.Is(err, ErrEvidenceReaderUntrusted) {
		_ = tx.Rollback(ctx)
		t.Fatalf("overbroad PUBLIC SELECT RLS policy was accepted: %v", err)
	}
	_ = tx.Rollback(ctx)

	if _, err := owner.Exec(ctx, "DROP POLICY "+policy+
		" ON public.sandbox_agentd_attempts"); err != nil {
		t.Fatal(err)
	}
	if n := countForeign(); n != 0 {
		t.Fatalf("source RLS was not restored: foreign=%d", n)
	}
	tx, err = reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidenceReaderLogin(ctx, tx, ref.TenantID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("valid reader not restored after removing overbroad policy: %v", err)
	}
	_ = tx.Rollback(ctx)
}
