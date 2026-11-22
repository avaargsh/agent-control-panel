package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ensureOptimizationAttemptMigration adds an ACP-owned append-only journal.
// It does not enable a public verifier route or trust an Agent as issuer.
func ensureOptimizationAttemptMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		var partial bool
		if err := tx.QueryRow(ctx, `SELECT to_regclass('optimization_verification_attempts') IS NOT NULL
			OR to_regprocedure('reject_optimization_attempt_mutation()') IS NOT NULL`).Scan(&partial); err != nil {
			return err
		}
		if partial {
			return ErrSchemaDrift
		}
		sql := strings.TrimSpace(string(source))
		if !strings.HasPrefix(sql, "BEGIN;") || !strings.HasSuffix(sql, "COMMIT;") {
			return ErrSchemaDrift
		}
		sql = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(sql, "BEGIN;"), "COMMIT;"))
		if _, err := tx.Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol); err != nil {
			return fmt.Errorf("apply optimization attempt migration v13: %w", err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			optimizationAttemptMigrationVersion, optimizationAttemptMigrationName, checksum); err != nil {
			return fmt.Errorf("record optimization attempt migration: %w", err)
		}
	}
	return verifyOptimizationAttemptSchema(ctx, tx, source)
}

func verifyOptimizationAttemptSchema(ctx context.Context, tx pgx.Tx, source []byte) error {
	var relation bool
	if err := tx.QueryRow(ctx, `SELECT count(*)=1 FROM pg_class c
		WHERE c.oid=to_regclass('optimization_verification_attempts')
		  AND c.relnamespace=current_schema()::regnamespace
		  AND c.relkind='r' AND c.relpersistence='p'
		  AND c.relrowsecurity AND c.relforcerowsecurity`).Scan(&relation); err != nil {
		return err
	}
	if !relation {
		return ErrSchemaDrift
	}
	// A tenant-scoped app.* GUC is not authentication. Until issuer/consumer
	// service role provisioning is separately approved, migration v13 grants
	// no table/column/function access to any non-owner, including PUBLIC.
	// Reject later out-of-band grants on EVERY startup; names and RLS flags
	// alone cannot detect ACL escalation.
	var nonOwnerGrants bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_class c
			CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) acl
			WHERE c.oid=to_regclass('optimization_verification_attempts')
			  AND acl.grantee<>c.relowner
		) OR EXISTS (
			SELECT 1 FROM pg_class c
			JOIN pg_attribute a ON a.attrelid=c.oid
			CROSS JOIN LATERAL aclexplode(a.attacl) acl
			WHERE c.oid=to_regclass('optimization_verification_attempts')
			  AND a.attnum>0 AND NOT a.attisdropped
			  AND acl.grantee<>c.relowner
		) OR EXISTS (
			SELECT 1 FROM pg_proc p
			CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
			WHERE p.oid=to_regprocedure('reject_optimization_attempt_mutation()')
			  AND acl.grantee<>p.proowner
		)
	`).Scan(&nonOwnerGrants); err != nil {
		return fmt.Errorf("verify optimization attempt privilege grants: %w", err)
	}
	if nonOwnerGrants {
		return ErrSchemaDrift
	}
	// Compile the exact v13 partial UNIQUE index on the same PostgreSQL
	// engine: same-name, same-uniqueness indexes may still use weaker key
	// columns or predicate. Neither name nor i.indpred != NULL is proof.
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE acp_expected_optimization_index (
			tenant_id text, project_id text, verifier_run_id text, consumed_at timestamptz
		) ON COMMIT DROP;
		CREATE UNIQUE INDEX acp_expected_optimization_verifier_run_unique
			ON pg_temp.acp_expected_optimization_index (tenant_id,project_id,verifier_run_id)
			WHERE consumed_at IS NOT NULL;
	`, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("compile expected verifier Run deduplication index: %w", err)
	}
	var keys bool
	if err := tx.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conrelid=to_regclass('optimization_verification_attempts')
		  AND c.conname='optimization_verification_attempts_pkey' AND c.contype='p' AND c.convalidated
		  AND (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
		       FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinality)
		       JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum)
			  = ARRAY['verification_nonce']::text[])
		AND (SELECT count(*) FROM pg_constraint c WHERE c.conrelid=to_regclass('optimization_verification_attempts')
		  AND c.conname IN ('optimization_attempt_lifetime','optimization_attempt_consumption_consistency')
		  AND c.contype='c' AND c.convalidated)=2
		AND EXISTS (
		  SELECT 1 FROM pg_index i
		  JOIN pg_class c ON c.oid=i.indexrelid
		  JOIN pg_index expected ON expected.indrelid=to_regclass('pg_temp.acp_expected_optimization_index')
		  WHERE i.indrelid=to_regclass('optimization_verification_attempts')
		    AND c.relname='optimization_attempt_verifier_run_unique'
		    AND i.indisvalid AND i.indisready AND i.indisunique
		    AND i.indnkeyatts=3 AND i.indnatts=3 AND i.indexprs IS NULL
		    AND pg_get_indexdef(i.indexrelid,1,false)=pg_get_indexdef(expected.indexrelid,1,false)
		    AND pg_get_indexdef(i.indexrelid,2,false)=pg_get_indexdef(expected.indexrelid,2,false)
		    AND pg_get_indexdef(i.indexrelid,3,false)=pg_get_indexdef(expected.indexrelid,3,false)
		    AND pg_get_expr(i.indpred,i.indrelid,false)=pg_get_expr(expected.indpred,expected.indrelid,false)
		)`).Scan(&keys); err != nil {
		return err
	}
	if !keys {
		return ErrSchemaDrift
	}
	if err := verifyOptimizationAttemptChecks(ctx, tx, source); err != nil {
		return err
	}
	// Compile the reviewed RLS scope in the same PostgreSQL instance to
	// compare its normalized expression, rather than checking only names.
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE acp_expected_optimization_scope (tenant_id text, project_id text) ON COMMIT DROP;
		CREATE POLICY optimization_attempt_scope ON pg_temp.acp_expected_optimization_scope FOR ALL
		  USING (tenant_id=current_setting('app.tenant_id',true)
		     AND project_id=current_setting('app.project_id',true))
		  WITH CHECK (tenant_id=current_setting('app.tenant_id',true)
		     AND project_id=current_setting('app.project_id',true));`, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("compile expected optimization scope: %w", err)
	}
	var policy bool
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM pg_policy WHERE polrelid=to_regclass('optimization_verification_attempts'))=1
		AND (SELECT count(*) FROM pg_policy a JOIN pg_policy e ON e.polname=a.polname
		     AND e.polrelid=to_regclass('pg_temp.acp_expected_optimization_scope')
		  WHERE a.polrelid=to_regclass('optimization_verification_attempts')
		    AND a.polname='optimization_attempt_scope' AND a.polcmd='*'
		    AND a.polpermissive AND a.polroles=e.polroles
		    AND pg_get_expr(a.polqual,a.polrelid,false)=pg_get_expr(e.polqual,e.polrelid,false)
		    AND pg_get_expr(a.polwithcheck,a.polrelid,false)=pg_get_expr(e.polwithcheck,e.polrelid,false))=1`).Scan(&policy); err != nil {
		return err
	}
	if !policy {
		return ErrSchemaDrift
	}
	var body string
	if err := tx.QueryRow(ctx, `SELECT p.prosrc FROM pg_proc p
		WHERE p.oid=to_regprocedure('reject_optimization_attempt_mutation()')
		  AND p.pronargs=0 AND p.prokind='f'
		  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
		  AND p.prorettype='pg_catalog.trigger'::regtype
		  AND p.provolatile='v' AND NOT p.prosecdef AND p.proconfig IS NULL`).Scan(&body); errors.Is(err, pgx.ErrNoRows) {
		return ErrSchemaDrift
	} else if err != nil {
		return err
	}
	parts := strings.Split(string(source), "$attempt$")
	if len(parts) != 3 || strings.TrimSpace(body) != strings.TrimSpace(parts[1]) {
		return ErrSchemaDrift
	}
	var triggers bool
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM pg_trigger t
		  WHERE t.tgrelid=to_regclass('optimization_verification_attempts')
		    AND NOT t.tgisinternal AND t.tgenabled='A'
		    AND t.tgfoid=to_regprocedure('reject_optimization_attempt_mutation()')
		    AND ((t.tgname='optimization_attempt_no_reset_or_delete' AND t.tgtype=27)
		      OR (t.tgname='optimization_attempt_no_truncate' AND t.tgtype=34)))=2`).Scan(&triggers); err != nil {
		return err
	}
	if !triggers {
		return ErrSchemaDrift
	}
	return nil
}
