package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

func ensureBlobStageMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		var partial bool
		if err := tx.QueryRow(ctx, `
			SELECT to_regclass('workspace_blob_stages') IS NOT NULL
				OR to_regclass('workspace_blob_commit_refs') IS NOT NULL
				OR to_regprocedure('reject_workspace_blob_evidence_mutation()') IS NOT NULL
		`).Scan(&partial); err != nil {
			return fmt.Errorf("inspect partial blob-stage migration: %w", err)
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
			return fmt.Errorf("apply Workspace blob stage migration v7: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			blobStageMigrationVersion, blobStageMigrationName, checksum,
		); err != nil {
			return fmt.Errorf("record blob stage migration v7: %w", err)
		}
	}
	return verifyBlobStageSchema(ctx, tx)
}

func verifyBlobStageSchema(ctx context.Context, tx pgx.Tx) error {
	var protected bool
	if err := tx.QueryRow(ctx, `
		SELECT count(*)=2 FROM pg_class c
		WHERE c.oid IN (to_regclass('workspace_blob_stages'),to_regclass('workspace_blob_commit_refs'))
		  AND c.relnamespace=current_schema()::regnamespace
		  AND c.relkind='r' AND c.relpersistence='p'
		  AND c.relrowsecurity AND c.relforcerowsecurity
	`).Scan(&protected); err != nil {
		return fmt.Errorf("verify blob evidence table durability/RLS: %w", err)
	}
	if !protected {
		return ErrSchemaDrift
	}
	var columns bool
	if err := tx.QueryRow(ctx, `
		WITH expected(rel,col,typ) AS (
			VALUES
			  ('workspace_blob_stages','tenant_id','text'::regtype),
			  ('workspace_blob_stages','workspace_id','text'::regtype),
			  ('workspace_blob_stages','owner_principal_id','text'::regtype),
			  ('workspace_blob_stages','stage_id','text'::regtype),
			  ('workspace_blob_stages','source_run_intent_id','uuid'::regtype),
			  ('workspace_blob_stages','session_id','text'::regtype),
			  ('workspace_blob_stages','das_digest','text'::regtype),
			  ('workspace_blob_stages','asset_path','text'::regtype),
			  ('workspace_blob_stages','artifact_digest','text'::regtype),
			  ('workspace_blob_stages','size_bytes','bigint'::regtype),
			  ('workspace_blob_stages','lease_seconds','bigint'::regtype),
			  ('workspace_blob_stages','created_at','timestamptz'::regtype),
			  ('workspace_blob_stages','expires_at','timestamptz'::regtype),
			  ('workspace_blob_commit_refs','tenant_id','text'::regtype),
			  ('workspace_blob_commit_refs','workspace_id','text'::regtype),
			  ('workspace_blob_commit_refs','owner_principal_id','text'::regtype),
			  ('workspace_blob_commit_refs','manifest_revision','bigint'::regtype),
			  ('workspace_blob_commit_refs','asset_path','text'::regtype),
			  ('workspace_blob_commit_refs','artifact_digest','text'::regtype),
			  ('workspace_blob_commit_refs','size_bytes','bigint'::regtype)
		)
		SELECT count(*)=(SELECT count(*) FROM expected)
		FROM expected e JOIN pg_attribute a
		  ON a.attrelid=to_regclass(e.rel) AND a.attname=e.col
		 AND a.atttypid=e.typ AND a.attnotnull
		 AND a.attnum>0 AND NOT a.attisdropped
	`).Scan(&columns); err != nil {
		return fmt.Errorf("verify blob evidence column contracts: %w", err)
	}
	if !columns {
		return ErrSchemaDrift
	}

	var relations bool
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
			WHERE c.conrelid IN (to_regclass('workspace_blob_stages'),to_regclass('workspace_blob_commit_refs'))
			  AND c.convalidated
		)
		SELECT
		  EXISTS(SELECT 1 FROM keys WHERE conname='workspace_blob_stages_pkey' AND contype='p'
		      AND local_cols=ARRAY['tenant_id','workspace_id','stage_id']::text[])
		  AND EXISTS(SELECT 1 FROM keys WHERE conname='workspace_blob_commit_refs_pkey' AND contype='p'
		      AND local_cols=ARRAY['tenant_id','workspace_id','manifest_revision','asset_path']::text[])
		  AND EXISTS(SELECT 1 FROM keys WHERE conname='workspace_blob_stage_owner_fkey' AND contype='f'
		      AND confrelid=to_regclass('research_workspaces')
		      AND confupdtype='r' AND confdeltype='r'
		      AND local_cols=ARRAY['tenant_id','workspace_id','owner_principal_id']::text[]
		      AND remote_cols=ARRAY['tenant_id','workspace_id','owner_principal_id']::text[])
		  AND EXISTS(SELECT 1 FROM keys WHERE conname='workspace_blob_stage_source_fkey' AND contype='f'
		      AND confrelid=to_regclass('run_capability_locks')
		      AND confupdtype='r' AND confdeltype='r'
		      AND local_cols=ARRAY['source_run_intent_id','tenant_id','owner_principal_id','workspace_id','session_id','das_digest']::text[]
		      AND remote_cols=ARRAY['run_intent_id','tenant_id','principal_id','workspace_id','session_id','artifact_digest']::text[])
		  AND EXISTS(SELECT 1 FROM keys WHERE conname='workspace_blob_ref_manifest_fkey' AND contype='f'
		      AND confrelid=to_regclass('workspace_manifest_commits')
		      AND confupdtype='r' AND confdeltype='r'
		      AND local_cols=ARRAY['tenant_id','workspace_id','manifest_revision']::text[]
		      AND remote_cols=ARRAY['tenant_id','workspace_id','manifest_revision']::text[])
	`).Scan(&relations); err != nil {
		return fmt.Errorf("verify staged blob ownership FKs: %w", err)
	}
	if !relations {
		return ErrSchemaDrift
	}

	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE acp_expected_blob_scope (
			tenant_id text, owner_principal_id text
		) ON COMMIT DROP;
		CREATE POLICY workspace_blob_stage_scope ON pg_temp.acp_expected_blob_scope
			FOR ALL
			USING (tenant_id=current_setting('app.tenant_id',true)
				AND owner_principal_id=current_setting('app.principal_id',true))
			WITH CHECK (tenant_id=current_setting('app.tenant_id',true)
				AND owner_principal_id=current_setting('app.principal_id',true));
	`, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("compile blob scope policy: %w", err)
	}
	var policies bool
	if err := tx.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM pg_policy WHERE polrelid=to_regclass('workspace_blob_stages'))=1
		   AND (SELECT count(*) FROM pg_policy WHERE polrelid=to_regclass('workspace_blob_commit_refs'))=1
		   AND (SELECT count(*) FROM pg_policy a JOIN pg_policy e
		        ON e.polrelid=to_regclass('pg_temp.acp_expected_blob_scope')
		        WHERE a.polrelid IN (to_regclass('workspace_blob_stages'),to_regclass('workspace_blob_commit_refs'))
		          AND a.polcmd='*' AND a.polpermissive AND a.polroles=e.polroles
		          AND a.polname IN ('workspace_blob_stage_scope','workspace_blob_ref_scope')
		          AND pg_get_expr(a.polqual,a.polrelid,false)=pg_get_expr(e.polqual,e.polrelid,false)
		          AND pg_get_expr(a.polwithcheck,a.polrelid,false)=pg_get_expr(e.polwithcheck,e.polrelid,false)
		       )=2
	`).Scan(&policies); err != nil {
		return fmt.Errorf("verify blob scope policies: %w", err)
	}
	if !policies {
		return ErrSchemaDrift
	}
	var triggers bool
	if err := tx.QueryRow(ctx, `
		SELECT
		   (SELECT count(*) FROM pg_trigger t
		    WHERE t.tgrelid=to_regclass('workspace_blob_stages') AND NOT t.tgisinternal
		      AND t.tgenabled='O' AND t.tgfoid=to_regprocedure('reject_workspace_blob_evidence_mutation()')
		      AND ((t.tgname='workspace_blob_stages_no_update_delete' AND t.tgtype=27)
		        OR (t.tgname='workspace_blob_stages_no_truncate' AND t.tgtype=34)))=2
		   AND (SELECT count(*) FROM pg_trigger t
		    WHERE t.tgrelid=to_regclass('workspace_blob_commit_refs') AND NOT t.tgisinternal
		      AND t.tgenabled='O' AND t.tgfoid=to_regprocedure('reject_workspace_blob_evidence_mutation()')
		      AND ((t.tgname='workspace_blob_refs_no_update_delete' AND t.tgtype=27)
		        OR (t.tgname='workspace_blob_refs_no_truncate' AND t.tgtype=34)))=2
	`).Scan(&triggers); err != nil {
		return fmt.Errorf("verify blob evidence immutability triggers: %w", err)
	}
	if !triggers {
		return ErrSchemaDrift
	}
	var body string
	if err := tx.QueryRow(ctx, `
		SELECT p.prosrc FROM pg_proc p
		WHERE p.oid=to_regprocedure('reject_workspace_blob_evidence_mutation()')
		  AND p.pronargs=0 AND p.prokind='f'
		  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
		  AND p.prorettype='trigger'::regtype
		  AND p.provolatile='v' AND NOT p.prosecdef AND p.proconfig IS NULL
	`).Scan(&body); errors.Is(err, pgx.ErrNoRows) {
		return ErrSchemaDrift
	} else if err != nil {
		return fmt.Errorf("verify blob evidence guard body: %w", err)
	}
	if strings.TrimSpace(body) != "BEGIN\n    RAISE EXCEPTION 'Workspace blob evidence is immutable';\nEND;" {
		return ErrSchemaDrift
	}
	return nil
}
