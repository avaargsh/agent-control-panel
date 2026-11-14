package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

func ensureRunCapabilityLockMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		var partial bool
		if err := tx.QueryRow(ctx, `
			SELECT to_regclass('run_capability_locks') IS NOT NULL
			    OR to_regclass('run_intents_capability_parent_identity') IS NOT NULL
			    OR to_regprocedure('reject_run_capability_lock_mutation()') IS NOT NULL
		`).Scan(&partial); err != nil {
			return fmt.Errorf("inspect partial DAS lock migration: %w", err)
		}
		if partial {
			return ErrSchemaDrift
		}
		sql := strings.TrimSpace(string(source))
		sql = strings.TrimPrefix(sql, "BEGIN;")
		sql = strings.TrimSuffix(strings.TrimSpace(sql), "COMMIT;")
		sql = strings.TrimSpace(sql)
		if sql == "" || sql == strings.TrimSpace(string(source)) {
			return ErrSchemaDrift
		}
		if _, err := tx.Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol); err != nil {
			return fmt.Errorf("apply DAS lock migration v5: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			capabilityLockMigrationVersion, capabilityLockMigrationName, checksum,
		); err != nil {
			return fmt.Errorf("record DAS lock migration v5: %w", err)
		}
	}
	return verifyRunCapabilityLockSchema(ctx, tx)
}

func verifyRunCapabilityLockSchema(ctx context.Context, tx pgx.Tx) error {
	var durableAndIsolated bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_class c
			WHERE c.oid=to_regclass('run_capability_locks')
			  AND c.relnamespace=current_schema()::regnamespace
			  AND c.relkind='r' AND c.relpersistence='p'
			  AND c.relrowsecurity AND c.relforcerowsecurity
		)
	`).Scan(&durableAndIsolated); err != nil {
		return fmt.Errorf("verify DAS lock storage/RLS: %w", err)
	}
	if !durableAndIsolated {
		return ErrSchemaDrift
	}
	var columnsBound bool
	if err := tx.QueryRow(ctx, `
		WITH expected(name, typ) AS (
			VALUES
			  ('run_intent_id', 'uuid'::regtype),
			  ('tenant_id', 'text'::regtype),
			  ('principal_id', 'text'::regtype),
			  ('agent_release_id', 'text'::regtype),
			  ('workspace_id', 'text'::regtype),
			  ('session_id', 'text'::regtype),
			  ('package_id', 'text'::regtype),
			  ('package_version', 'text'::regtype),
			  ('artifact_digest', 'text'::regtype),
			  ('subscription_id', 'text'::regtype),
			  ('policy_revision', 'text'::regtype),
			  ('created_at', 'timestamp with time zone'::regtype)
		)
		SELECT count(*)=(SELECT count(*) FROM expected)
		FROM expected e JOIN pg_attribute a
		  ON a.attrelid=to_regclass('run_capability_locks')
		 AND a.attname=e.name AND a.atttypid=e.typ AND a.attnotnull
		 AND a.attnum>0 AND NOT a.attisdropped
	`).Scan(&columnsBound); err != nil {
		return fmt.Errorf("verify DAS lock columns: %w", err)
	}
	if !columnsBound {
		return ErrSchemaDrift
	}
	var indexesBound bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_index i
			WHERE i.indexrelid=to_regclass('run_intents_capability_parent_identity')
			  AND i.indrelid=to_regclass('run_intents')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate
			  AND (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
			       FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS k(attnum,ordinality)
			       JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      =ARRAY['id','tenant_id','principal_id','release_id','session_id']::text[]
		)
	`).Scan(&indexesBound); err != nil {
		return fmt.Errorf("verify DAS lock parent identity index: %w", err)
	}
	if !indexesBound {
		return ErrSchemaDrift
	}
	var constraintCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_constraint c
		WHERE c.conrelid=to_regclass('run_capability_locks') AND c.convalidated
		  AND (
			(c.conname='run_capability_locks_pkey' AND c.contype='p'
			 AND (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
			      FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinality)
			      JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum)
			      =ARRAY['run_intent_id']::text[])
			OR
			(c.conname='run_capability_lock_origin_fkey' AND c.contype='f'
			 AND c.confrelid=to_regclass('run_intents')
			 AND c.confupdtype='r' AND c.confdeltype='r'
			 AND (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
			      FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinality)
			      JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum)
			     =ARRAY['run_intent_id','tenant_id','principal_id','agent_release_id','session_id']::text[]
			 AND (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
			      FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum,ordinality)
			      JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum)
			     =ARRAY['id','tenant_id','principal_id','release_id','session_id']::text[])
		  )
	`).Scan(&constraintCount); err != nil {
		return fmt.Errorf("verify DAS lock key/foreign constraints: %w", err)
	}
	if constraintCount != 2 {
		return ErrSchemaDrift
	}
	// Compare policy expressions against SQL compiled on the *same* server.
	_, err := tx.Exec(ctx, `
		CREATE TEMP TABLE acp_expected_das_policy (tenant_id text) ON COMMIT DROP;
		CREATE POLICY run_capability_locks_tenant ON pg_temp.acp_expected_das_policy
			FOR ALL
			USING (tenant_id = current_setting('app.tenant_id', true))
			WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
	`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		return fmt.Errorf("compile expected DAS lock tenant policy: %w", err)
	}
	var policyBound bool
	if err := tx.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM pg_policy
		        WHERE polrelid=to_regclass('run_capability_locks'))=1
		   AND EXISTS (
			SELECT 1
			FROM pg_policy a JOIN pg_policy e ON e.polname=a.polname
			WHERE a.polrelid=to_regclass('run_capability_locks')
			  AND e.polrelid=to_regclass('pg_temp.acp_expected_das_policy')
			  AND a.polname='run_capability_locks_tenant'
			  AND a.polcmd='*' AND a.polpermissive
			  AND a.polroles=e.polroles
			  AND pg_get_expr(a.polqual,a.polrelid,false)
			      =pg_get_expr(e.polqual,e.polrelid,false)
			  AND pg_get_expr(a.polwithcheck,a.polrelid,false)
			      =pg_get_expr(e.polwithcheck,e.polrelid,false)
		)
	`).Scan(&policyBound); err != nil {
		return fmt.Errorf("verify DAS lock RLS policy: %w", err)
	}
	if !policyBound {
		return ErrSchemaDrift
	}
	var functionBody string
	if err := tx.QueryRow(ctx, `
		SELECT p.prosrc FROM pg_proc p
		WHERE p.oid=to_regprocedure('reject_run_capability_lock_mutation()')
		  AND p.pronargs=0 AND p.prokind='f'
		  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
		  AND p.prorettype='trigger'::regtype
		  AND p.provolatile='v' AND NOT p.prosecdef AND p.proconfig IS NULL
	`).Scan(&functionBody); errors.Is(err, pgx.ErrNoRows) {
		return ErrSchemaDrift
	} else if err != nil {
		return fmt.Errorf("verify DAS lock immutable function: %w", err)
	}
	if strings.TrimSpace(functionBody) != "BEGIN\n    RAISE EXCEPTION 'RunIntent capability lock is immutable';\nEND;" {
		return ErrSchemaDrift
	}
	var triggerCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_trigger t
		WHERE t.tgrelid=to_regclass('run_capability_locks')
		  AND NOT t.tgisinternal AND t.tgenabled='O'
		  AND t.tgfoid=to_regprocedure('reject_run_capability_lock_mutation()')
		  AND (
			(t.tgname='run_capability_lock_no_update_delete' AND t.tgtype=27)
			OR
			(t.tgname='run_capability_lock_no_truncate' AND t.tgtype=34)
		  )
	`).Scan(&triggerCount); err != nil {
		return fmt.Errorf("verify DAS lock mutation triggers: %w", err)
	}
	if triggerCount != 2 {
		return ErrSchemaDrift
	}
	return nil
}
