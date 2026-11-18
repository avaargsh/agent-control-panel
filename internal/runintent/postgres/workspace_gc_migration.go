package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

func ensureGCClaimMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		var partial bool
		if err := tx.QueryRow(ctx, `
			SELECT to_regclass('workspace_gc_claims') IS NOT NULL
				OR to_regclass('workspace_gc_observations') IS NOT NULL
				OR to_regprocedure('reject_workspace_gc_identity_mutation()') IS NOT NULL
		`).Scan(&partial); err != nil {
			return fmt.Errorf("inspect partial GC migration v9: %w", err)
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
			return fmt.Errorf("apply GC claim migration v9: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			gcClaimMigrationVersion, gcClaimMigrationName, checksum,
		); err != nil {
			return fmt.Errorf("record GC claim migration v9: %w", err)
		}
	}
	return verifyGCClaimSchema(ctx, tx)
}

func verifyGCClaimSchema(ctx context.Context, tx pgx.Tx) error {
	var durable bool
	if err := tx.QueryRow(ctx, `
		SELECT count(*)=2 FROM pg_class c
		WHERE c.oid IN (to_regclass('workspace_gc_claims'),to_regclass('workspace_gc_observations'))
		  AND c.relnamespace=current_schema()::regnamespace
		  AND c.relkind='r' AND c.relpersistence='p'
		  AND c.relrowsecurity AND c.relforcerowsecurity
	`).Scan(&durable); err != nil {
		return fmt.Errorf("verify GC evidence durability/FORCE RLS: %w", err)
	}
	if !durable {
		return ErrSchemaDrift
	}
	var fields bool
	if err := tx.QueryRow(ctx, `
		WITH expected(rel,col,typ) AS (
			VALUES
			  ('workspace_gc_claims','tenant_id','text'::regtype),
			  ('workspace_gc_claims','workspace_id','text'::regtype),
			  ('workspace_gc_claims','owner_principal_id','text'::regtype),
			  ('workspace_gc_claims','artifact_digest','text'::regtype),
			  ('workspace_gc_claims','holder_id','text'::regtype),
			  ('workspace_gc_claims','generation','bigint'::regtype),
			  ('workspace_gc_claims','lease_seconds','bigint'::regtype),
			  ('workspace_gc_claims','created_at','timestamptz'::regtype),
			  ('workspace_gc_claims','updated_at','timestamptz'::regtype),
			  ('workspace_gc_claims','expires_at','timestamptz'::regtype),
			  ('workspace_gc_observations','observation_id','bigint'::regtype),
			  ('workspace_gc_observations','tenant_id','text'::regtype),
			  ('workspace_gc_observations','workspace_id','text'::regtype),
			  ('workspace_gc_observations','owner_principal_id','text'::regtype),
			  ('workspace_gc_observations','artifact_digest','text'::regtype),
			  ('workspace_gc_observations','holder_id','text'::regtype),
			  ('workspace_gc_observations','generation','bigint'::regtype),
			  ('workspace_gc_observations','disposition','text'::regtype),
			  ('workspace_gc_observations','observed_at','timestamptz'::regtype)
		)
		SELECT count(*)=(SELECT count(*) FROM expected)
		FROM expected e JOIN pg_attribute a ON a.attrelid=to_regclass(e.rel)
		  AND a.attname=e.col AND a.atttypid=e.typ
		  AND a.attnotnull AND a.attnum>0 AND NOT a.attisdropped
	`).Scan(&fields); err != nil {
		return fmt.Errorf("verify GC claim/observation columns: %w", err)
	}
	if !fields {
		return ErrSchemaDrift
	}
	var keys bool
	if err := tx.QueryRow(ctx, `
		WITH keys AS (
			SELECT c.conname,c.contype,c.confrelid,c.confupdtype,c.confdeltype,
			  (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
			   FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinality)
			   JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum) AS local_cols,
			  (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
			   FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum,ordinality)
			   JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum) AS remote_cols
			FROM pg_constraint c
			WHERE c.conrelid IN (to_regclass('workspace_gc_claims'),to_regclass('workspace_gc_observations'))
			  AND c.convalidated
		)
		SELECT
		  EXISTS (SELECT 1 FROM keys
		    WHERE conname='workspace_gc_claims_pkey' AND contype='p'
		    AND local_cols=ARRAY['tenant_id','workspace_id','artifact_digest']::text[])
		  AND EXISTS (SELECT 1 FROM keys
		    WHERE conname='workspace_gc_claims_owner_key' AND contype='u'
		    AND local_cols=ARRAY['tenant_id','workspace_id','artifact_digest','owner_principal_id']::text[])
		  AND EXISTS (SELECT 1 FROM keys
		    WHERE conname='workspace_gc_claims_owner_fkey' AND contype='f'
		    AND confrelid=to_regclass('research_workspaces')
		    AND confupdtype='r' AND confdeltype='r'
		    AND local_cols=ARRAY['tenant_id','workspace_id','owner_principal_id']::text[]
		    AND remote_cols=ARRAY['tenant_id','workspace_id','owner_principal_id']::text[])
		  AND EXISTS (SELECT 1 FROM keys
		    WHERE conname='workspace_gc_observations_pkey' AND contype='p'
		    AND local_cols=ARRAY['observation_id']::text[])
		  AND EXISTS (SELECT 1 FROM keys
		    WHERE conname='workspace_gc_observations_owner_fkey' AND contype='f'
		    AND confrelid=to_regclass('research_workspaces')
		    AND confupdtype='r' AND confdeltype='r'
		    AND local_cols=ARRAY['tenant_id','workspace_id','owner_principal_id']::text[]
		    AND remote_cols=ARRAY['tenant_id','workspace_id','owner_principal_id']::text[])
	`).Scan(&keys); err != nil {
		return fmt.Errorf("verify GC claim ownership and unique keys: %w", err)
	}
	if !keys {
		return ErrSchemaDrift
	}

	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE acp_expected_gc_scope (
			tenant_id text, owner_principal_id text
		) ON COMMIT DROP;
		CREATE POLICY workspace_gc_claim_scope ON pg_temp.acp_expected_gc_scope FOR ALL
			USING (tenant_id=current_setting('app.tenant_id',true)
			  AND owner_principal_id=current_setting('app.principal_id',true))
			WITH CHECK (tenant_id=current_setting('app.tenant_id',true)
			  AND owner_principal_id=current_setting('app.principal_id',true));
	`, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("compile expected GC RLS policy: %w", err)
	}
	var policies bool
	if err := tx.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM pg_policy WHERE polrelid=to_regclass('workspace_gc_claims'))=1
		  AND (SELECT count(*) FROM pg_policy WHERE polrelid=to_regclass('workspace_gc_observations'))=1
		  AND (SELECT count(*) FROM pg_policy a JOIN pg_policy e
		       ON e.polrelid=to_regclass('pg_temp.acp_expected_gc_scope')
		       WHERE a.polrelid IN (to_regclass('workspace_gc_claims'),to_regclass('workspace_gc_observations'))
		         AND a.polcmd='*' AND a.polpermissive AND a.polroles=e.polroles
		         AND a.polname IN ('workspace_gc_claim_scope','workspace_gc_observation_scope')
		         AND pg_get_expr(a.polqual,a.polrelid,false)=pg_get_expr(e.polqual,e.polrelid,false)
		         AND pg_get_expr(a.polwithcheck,a.polrelid,false)=pg_get_expr(e.polwithcheck,e.polrelid,false)
		      )=2
	`).Scan(&policies); err != nil {
		return fmt.Errorf("verify GC claims tenant/principal policies: %w", err)
	}
	if !policies {
		return ErrSchemaDrift
	}
	var triggers bool
	if err := tx.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM pg_trigger t
		   WHERE t.tgrelid=to_regclass('workspace_gc_claims')
		     AND NOT t.tgisinternal AND t.tgenabled='O'
		     AND t.tgfoid=to_regprocedure('reject_workspace_gc_identity_mutation()')
		     AND ((t.tgname='workspace_gc_claims_no_identity_change' AND t.tgtype=19)
		       OR (t.tgname='workspace_gc_claims_no_delete' AND t.tgtype=11)
		       OR (t.tgname='workspace_gc_claims_no_truncate' AND t.tgtype=34)))=3
		  AND (SELECT count(*) FROM pg_trigger t
		   WHERE t.tgrelid=to_regclass('workspace_gc_observations')
		     AND NOT t.tgisinternal AND t.tgenabled='O'
		     AND t.tgfoid=to_regprocedure('reject_workspace_gc_identity_mutation()')
		     AND ((t.tgname='workspace_gc_observations_no_update_delete' AND t.tgtype=27)
		       OR (t.tgname='workspace_gc_observations_no_truncate' AND t.tgtype=34)))=2
	`).Scan(&triggers); err != nil {
		return fmt.Errorf("verify GC immutability trigger wiring: %w", err)
	}
	if !triggers {
		return ErrSchemaDrift
	}
	var body string
	err := tx.QueryRow(ctx, `
		SELECT p.prosrc FROM pg_proc p
		WHERE p.oid=to_regprocedure('reject_workspace_gc_identity_mutation()')
		  AND p.pronargs=0 AND p.prokind='f'
		  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
		  AND p.prorettype='trigger'::regtype AND p.provolatile='v'
		  AND NOT p.prosecdef AND p.proconfig IS NULL
	`).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSchemaDrift
	}
	if err != nil {
		return fmt.Errorf("verify GC immutability function: %w", err)
	}
	if strings.TrimSpace(body) != "BEGIN\n    RAISE EXCEPTION 'Workspace GC identity cannot be mutated or removed';\nEND;" {
		return ErrSchemaDrift
	}
	return nil
}
