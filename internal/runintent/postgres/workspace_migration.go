package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

func ensureWorkspaceMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		var partial bool
		if err := tx.QueryRow(ctx, `
			SELECT to_regclass('research_workspaces') IS NOT NULL
				OR to_regclass('workspace_manifest_commits') IS NOT NULL
				OR to_regclass('run_capability_locks_workspace_identity') IS NOT NULL
				OR to_regprocedure('reject_workspace_identity_mutation()') IS NOT NULL
				OR to_regprocedure('reject_workspace_commit_mutation()') IS NOT NULL
		`).Scan(&partial); err != nil {
			return fmt.Errorf("inspect partial Workspace migration: %w", err)
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
			return fmt.Errorf("apply Workspace migration v6: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			workspaceMigrationVersion, workspaceMigrationName, checksum,
		); err != nil {
			return fmt.Errorf("record Workspace migration v6: %w", err)
		}
	}
	return verifyWorkspaceSchema(ctx, tx)
}

func verifyWorkspaceSchema(ctx context.Context, tx pgx.Tx) error {
	var tablesProtected bool
	if err := tx.QueryRow(ctx, `
		SELECT count(*)=2
		FROM pg_class c
		WHERE c.oid IN (to_regclass('research_workspaces'),to_regclass('workspace_manifest_commits'))
		  AND c.relnamespace=current_schema()::regnamespace
		  AND c.relkind='r' AND c.relpersistence='p'
		  AND c.relrowsecurity AND c.relforcerowsecurity
	`).Scan(&tablesProtected); err != nil {
		return fmt.Errorf("verify Workspace table durability/RLS: %w", err)
	}
	if !tablesProtected {
		return ErrSchemaDrift
	}
	var ownerColumns bool
	if err := tx.QueryRow(ctx, `
		WITH expected(rel,col,typ) AS (
			VALUES
			  ('research_workspaces','tenant_id','text'::regtype),
			  ('research_workspaces','workspace_id','text'::regtype),
			  ('research_workspaces','owner_principal_id','text'::regtype),
			  ('research_workspaces','manifest_revision','bigint'::regtype),
			  ('workspace_manifest_commits','tenant_id','text'::regtype),
			  ('workspace_manifest_commits','workspace_id','text'::regtype),
			  ('workspace_manifest_commits','owner_principal_id','text'::regtype),
			  ('workspace_manifest_commits','manifest_revision','bigint'::regtype),
			  ('workspace_manifest_commits','previous_revision','bigint'::regtype),
			  ('workspace_manifest_commits','commit_id','text'::regtype),
			  ('workspace_manifest_commits','source_run_intent_id','uuid'::regtype),
			  ('workspace_manifest_commits','session_id','text'::regtype),
			  ('workspace_manifest_commits','das_digest','text'::regtype),
			  ('workspace_manifest_commits','manifest_digest','text'::regtype),
			  ('workspace_manifest_commits','manifest','jsonb'::regtype)
		)
		SELECT count(*)=(SELECT count(*) FROM expected)
		FROM expected e JOIN pg_attribute a
		  ON a.attrelid=to_regclass(e.rel)
		 AND a.attname=e.col AND a.atttypid=e.typ AND a.attnotnull
		 AND a.attnum>0 AND NOT a.attisdropped
	`).Scan(&ownerColumns); err != nil {
		return fmt.Errorf("verify Workspace authoritative columns: %w", err)
	}
	if !ownerColumns {
		return ErrSchemaDrift
	}
	var indexBound bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_index i
			WHERE i.indexrelid=to_regclass('run_capability_locks_workspace_identity')
			  AND i.indrelid=to_regclass('run_capability_locks')
			  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate
			  AND (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
			       FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS k(attnum,ordinality)
			       JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum)
			      =ARRAY['run_intent_id','tenant_id','principal_id','workspace_id','session_id','artifact_digest']::text[]
		)
	`).Scan(&indexBound); err != nil {
		return fmt.Errorf("verify RunIntent-Workspace release binding index: %w", err)
	}
	if !indexBound {
		return ErrSchemaDrift
	}
	var keysBound bool
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
			WHERE c.conrelid IN (to_regclass('research_workspaces'),to_regclass('workspace_manifest_commits'))
			  AND c.convalidated
		)
		SELECT
		  EXISTS(SELECT 1 FROM keys WHERE conname='research_workspaces_pkey'
		      AND contype='p' AND local_cols=ARRAY['tenant_id','workspace_id']::text[])
		  AND EXISTS(SELECT 1 FROM keys WHERE conname='research_workspaces_owner_identity'
		      AND contype='u' AND local_cols=ARRAY['tenant_id','workspace_id','owner_principal_id']::text[])
		  AND EXISTS(SELECT 1 FROM keys WHERE conname='workspace_commit_pkey'
		      AND contype='p' AND local_cols=ARRAY['tenant_id','workspace_id','manifest_revision']::text[])
		  AND EXISTS(SELECT 1 FROM keys WHERE conname='workspace_commit_idempotency'
		      AND contype='u' AND local_cols=ARRAY['tenant_id','workspace_id','commit_id']::text[])
		  AND EXISTS(SELECT 1 FROM keys WHERE conname='workspace_commit_owner_fkey'
		      AND contype='f' AND confrelid=to_regclass('research_workspaces')
		      AND confupdtype='r' AND confdeltype='r'
		      AND local_cols=ARRAY['tenant_id','workspace_id','owner_principal_id']::text[]
		      AND remote_cols=ARRAY['tenant_id','workspace_id','owner_principal_id']::text[])
		  AND EXISTS(SELECT 1 FROM keys WHERE conname='workspace_commit_source_fkey'
		      AND contype='f' AND confrelid=to_regclass('run_capability_locks')
		      AND confupdtype='r' AND confdeltype='r'
		      AND local_cols=ARRAY['source_run_intent_id','tenant_id','owner_principal_id','workspace_id','session_id','das_digest']::text[]
		      AND remote_cols=ARRAY['run_intent_id','tenant_id','principal_id','workspace_id','session_id','artifact_digest']::text[])
	`).Scan(&keysBound); err != nil {
		return fmt.Errorf("verify Workspace keys/ownership foreign references: %w", err)
	}
	if !keysBound {
		return ErrSchemaDrift
	}

	// Compile the expected scope expression on this database server rather
	// than comparing potentially version-specific pg_get_expr SQL text.
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE acp_expected_workspace_policy (
			tenant_id text, owner_principal_id text
		) ON COMMIT DROP;
		CREATE POLICY research_workspace_scope ON pg_temp.acp_expected_workspace_policy
			FOR ALL
			USING (tenant_id = current_setting('app.tenant_id', true)
				AND owner_principal_id = current_setting('app.principal_id', true))
			WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
				AND owner_principal_id = current_setting('app.principal_id', true));
	`, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("compile expected Workspace RLS policy: %w", err)
	}
	var policiesBound bool
	if err := tx.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM pg_policy WHERE polrelid=to_regclass('research_workspaces'))=1
		   AND (SELECT count(*) FROM pg_policy WHERE polrelid=to_regclass('workspace_manifest_commits'))=1
		   AND (SELECT count(*) FROM pg_policy a, pg_policy e
		        WHERE a.polrelid IN (to_regclass('research_workspaces'),to_regclass('workspace_manifest_commits'))
		          AND e.polrelid=to_regclass('pg_temp.acp_expected_workspace_policy')
		          AND a.polcmd='*' AND a.polpermissive AND a.polroles=e.polroles
		          AND a.polname IN ('research_workspace_scope','workspace_manifest_scope')
		          AND pg_get_expr(a.polqual,a.polrelid,false)=pg_get_expr(e.polqual,e.polrelid,false)
		          AND pg_get_expr(a.polwithcheck,a.polrelid,false)=pg_get_expr(e.polwithcheck,e.polrelid,false)
		       )=2
	`).Scan(&policiesBound); err != nil {
		return fmt.Errorf("verify Workspace RLS policy bindings: %w", err)
	}
	if !policiesBound {
		return ErrSchemaDrift
	}
	var triggersBound bool
	if err := tx.QueryRow(ctx, `
		SELECT
		   (SELECT count(*) FROM pg_trigger t
		    WHERE t.tgrelid=to_regclass('research_workspaces')
		      AND NOT t.tgisinternal AND t.tgenabled='O'
		      AND t.tgfoid=to_regprocedure('reject_workspace_identity_mutation()')
		      AND ((t.tgname='research_workspace_no_identity_change' AND t.tgtype=19)
		        OR (t.tgname='research_workspace_no_delete' AND t.tgtype=11)))=2
		   AND
		   (SELECT count(*) FROM pg_trigger t
		    WHERE t.tgrelid=to_regclass('workspace_manifest_commits')
		      AND NOT t.tgisinternal AND t.tgenabled='O'
		      AND t.tgfoid=to_regprocedure('reject_workspace_commit_mutation()')
		      AND ((t.tgname='workspace_manifest_no_update_delete' AND t.tgtype=27)
		        OR (t.tgname='workspace_manifest_no_truncate' AND t.tgtype=34)))=2
		   AND
		   (SELECT count(*) FROM pg_trigger t
		    WHERE t.tgrelid=to_regclass('research_workspaces') AND NOT t.tgisinternal)=2
		   AND
		   (SELECT count(*) FROM pg_trigger t
		    WHERE t.tgrelid=to_regclass('workspace_manifest_commits') AND NOT t.tgisinternal)=2
	`).Scan(&triggersBound); err != nil {
		return fmt.Errorf("verify Workspace mutation triggers: %w", err)
	}
	if !triggersBound {
		return ErrSchemaDrift
	}
	for name, expected := range map[string]string{
		"reject_workspace_identity_mutation": "BEGIN\n    RAISE EXCEPTION 'Workspace identity is immutable';\nEND;",
		"reject_workspace_commit_mutation":   "BEGIN\n    RAISE EXCEPTION 'Workspace commit receipt is immutable';\nEND;",
	} {
		var actual string
		err := tx.QueryRow(ctx, `
			SELECT p.prosrc FROM pg_proc p
			WHERE p.oid=to_regprocedure($1)
			  AND p.pronargs=0 AND p.prokind='f'
			  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
			  AND p.prorettype='trigger'::regtype
			  AND p.provolatile='v' AND NOT p.prosecdef AND p.proconfig IS NULL
		`, name+"()").Scan(&actual)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSchemaDrift
		}
		if err != nil {
			return fmt.Errorf("verify Workspace trigger function %s: %w", name, err)
		}
		if strings.TrimSpace(actual) != expected {
			return ErrSchemaDrift
		}
	}
	return nil
}
