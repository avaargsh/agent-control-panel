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

// A policy can be widened in place without adding any extra row. The
// old presence check (3 named policies, qual LIKE '%function%') erroneously
// accepted "tenant_id = tenant_func() OR true" and exposed foreign tenants.
func TestEvidenceReaderRejectsModifiedExpectedPolicy(t *testing.T) {
	owner := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	foreign := ref
	foreign.TenantID = "agentd-tenant-b"
	foreign.RunID = "22222222-2222-4222-8222-222222222222"
	foreign.CommandID = "foreign-inplace-policy"
	foreign.AttemptID = "foreign-inplace-attempt"
	foreign.ProviderCommandUID = "foreign-inplace-provider"
	seedAlreadyAuthorizedAttempt(t, owner, foreign)

	reader := newEvidenceReaderPool(t, owner, ref.TenantID)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	const policy = "agentd_attempt_evidence_reader_tenant"
	const table = "public.sandbox_agentd_attempts"
	var baselineQual string
	if err := owner.QueryRow(ctx,
		"SELECT qual FROM pg_catalog.pg_policies WHERE schemaname='public' AND tablename='sandbox_agentd_attempts' AND policyname=$1",
		policy).Scan(&baselineQual); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL expected source RLS qualification: %q", baselineQual)

	var count int
	if err := reader.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1",
		foreign.TenantID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("baseline foreign tenant evidence visible: count=%d err=%v", count, err)
	}
	check := func() error {
		t.Helper()
		tx, err := reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		return verifyEvidenceReaderLogin(ctx, tx, ref.TenantID)
	}
	if err := check(); err != nil {
		t.Fatalf("valid source RLS policy denied reader: %v", err)
	}
	if _, err := owner.Exec(ctx, "ALTER POLICY "+policy+" ON "+table+
		" USING ((tenant_id = public.sandbox_agentd_evidence_tenant()) OR true)"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := owner.Exec(context.Background(), "ALTER POLICY "+policy+" ON "+table+
			" USING (tenant_id = public.sandbox_agentd_evidence_tenant())"); err != nil {
			t.Errorf("restore legitimate tenant RLS policy: %v", err)
		}
	})
	if err := reader.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1",
		foreign.TenantID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("did not reproduce widened original PostgreSQL policy: count=%d err=%v", count, err)
	}
	if err := check(); !errors.Is(err, ErrEvidenceReaderUntrusted) {
		t.Fatalf("widened named tenant RLS policy was accepted: %v", err)
	}
	if _, err := owner.Exec(ctx, "ALTER POLICY "+policy+" ON "+table+
		" USING (tenant_id = public.sandbox_agentd_evidence_tenant())"); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Fatalf("legitimate RLS policy did not recover after restore: %v", err)
	}
}
