package agentd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The owner-owned SECURITY DEFINER tenant resolver is part of the RLS trust
// boundary. Its name, owner, volatility and search_path alone do not prove
// that it still binds the authenticated LOGIN name and PostgreSQL role OID.
// A changed function body that reads a caller-settable GUC must be rejected.
func TestEvidenceReaderRejectsTenantResolverFunctionBodyDrift(t *testing.T) {
	owner := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	foreign := ref
	foreign.TenantID = "agentd-tenant-b"
	foreign.RunID = "22222222-2222-4222-8222-222222222222"
	foreign.CommandID = "foreign-resolver-command"
	foreign.AttemptID = "foreign-resolver-attempt"
	foreign.ProviderCommandUID = "foreign-resolver-provider"
	seedAlreadyAuthorizedAttempt(t, owner, foreign)

	reader := newEvidenceReaderPool(t, owner, ref.TenantID)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Remember the literal source stored by PostgreSQL so cleanup reinstates
	// the precise 0016 body even when a regression assertion fails.
	var originalBody string
	if err := owner.QueryRow(ctx, "SELECT prosrc FROM pg_catalog.pg_proc WHERE oid=to_regprocedure('public.sandbox_agentd_evidence_tenant()')").Scan(&originalBody); err != nil {
		t.Fatal(err)
	}
	replaceBody := func(ctx context.Context, body string) error {
		_, err := owner.Exec(ctx, `CREATE OR REPLACE FUNCTION public.sandbox_agentd_evidence_tenant()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $acp_reader_resolver$`+body+`$acp_reader_resolver$;`)
		return err
	}
	t.Cleanup(func() {
		if err := replaceBody(context.Background(), originalBody); err != nil {
			t.Errorf("restore original 0016 trusted resolver body: %v", err)
		}
	})

	check := func(expectedTenant string) (error, int) {
		t.Helper()
		tx, err := reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		// A PostgreSQL reader credential can set custom GUCs even in a
		// read-only transaction; these must NEVER define tenant identity.
		if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", foreign.TenantID); err != nil {
			t.Fatal(err)
		}
		verdict := verifyEvidenceReaderLogin(ctx, tx, expectedTenant)
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_agentd_attempts WHERE tenant_id=$1", foreign.TenantID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return verdict, count
	}

	if verdict, count := check(foreign.TenantID); !errors.Is(verdict, ErrEvidenceReaderUntrusted) || count != 0 {
		t.Fatalf("baseline GUC spoofing leaked foreign tenant: verdict=%v rows=%d", verdict, count)
	}
	// Keep the original owner, name, role privileges, SECURITY DEFINER,
	// STABLE SQL language and trusted search_path; replace ONLY resolver
	// semantics with a caller-controlled value.
	if err := replaceBody(ctx, "\n    SELECT current_setting('app.tenant_id', true)\n"); err != nil {
		t.Fatal(err)
	}
	verdict, count := check(foreign.TenantID)
	if count != 1 {
		t.Fatalf("test did not reproduce cross-tenant read from altered source resolver: rows=%d", count)
	}
	if !errors.Is(verdict, ErrEvidenceReaderUntrusted) {
		t.Fatalf("untrusted SECURITY DEFINER tenant resolver body was accepted: %v", verdict)
	}

	if err := replaceBody(ctx, originalBody); err != nil {
		t.Fatal(err)
	}
	if verdict, count := check(foreign.TenantID); !errors.Is(verdict, ErrEvidenceReaderUntrusted) || count != 0 {
		t.Fatalf("legitimate resolver did not restore tenant isolation: verdict=%v rows=%d", verdict, count)
	}
}
