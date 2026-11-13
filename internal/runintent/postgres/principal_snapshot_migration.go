package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

func ensureRunIntentPrincipalSnapshotMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		var partial bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_attribute a
				WHERE a.attrelid=to_regclass('run_intents')
				  AND a.attname IN (
					'principal_snapshot_version','principal_subject_id',
					'principal_actor_id','principal_policy_revision','principal_config_digest'
				  )
				  AND a.attnum>0 AND NOT a.attisdropped
			) OR to_regprocedure('reject_run_intent_principal_snapshot_mutation()') IS NOT NULL
			  OR to_regprocedure('require_run_intent_principal_snapshot_for_dispatch()') IS NOT NULL
			  OR EXISTS (
				SELECT 1 FROM pg_trigger t
				WHERE t.tgrelid=to_regclass('run_intents')
				  AND t.tgname IN ('run_intent_principal_snapshot_immutable','run_intent_dispatch_requires_principal_snapshot')
			  )
		`).Scan(&partial); err != nil {
			return fmt.Errorf("inspect partial principal snapshot migration: %w", err)
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
			return fmt.Errorf("apply principal snapshot migration v4: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			principalSnapshotMigrationVersion, principalSnapshotMigrationName, checksum); err != nil {
			return fmt.Errorf("record principal snapshot migration v4: %w", err)
		}
	}
	return verifyRunIntentPrincipalSnapshotSchema(ctx, tx)
}

func verifyRunIntentPrincipalSnapshotSchema(ctx context.Context, tx pgx.Tx) error {
	var columnsBound bool
	if err := tx.QueryRow(ctx, `
		WITH expected(name, typ) AS (
			VALUES
			  ('principal_snapshot_version', 'pg_catalog.text'::regtype),
			  ('principal_subject_id', 'pg_catalog.text'::regtype),
			  ('principal_actor_id', 'pg_catalog.text'::regtype),
			  ('principal_policy_revision', 'pg_catalog.text'::regtype),
			  ('principal_config_digest', 'pg_catalog.text'::regtype)
		)
		SELECT count(*)=(SELECT count(*) FROM expected)
		FROM expected e
		JOIN pg_attribute a ON a.attrelid=to_regclass('run_intents')
		  AND a.attname=e.name AND a.atttypid=e.typ
		  AND NOT a.attnotnull AND NOT a.attisdropped
	`).Scan(&columnsBound); err != nil {
		return fmt.Errorf("verify principal snapshot columns: %w", err)
	}
	if !columnsBound {
		return ErrSchemaDrift
	}

	_, err := tx.Exec(ctx, `
		CREATE TEMP TABLE acp_expected_run_intent_principal_snapshot (
			project_id text,
			principal_snapshot_version text,
			principal_subject_id text,
			principal_actor_id text,
			principal_policy_revision text,
			principal_config_digest text
		) ON COMMIT DROP;
		ALTER TABLE pg_temp.acp_expected_run_intent_principal_snapshot
		  ADD CONSTRAINT run_intents_principal_snapshot_consistency CHECK (
			(
				principal_snapshot_version IS NULL AND
				principal_subject_id IS NULL AND
				principal_actor_id IS NULL AND
				principal_policy_revision IS NULL AND
				principal_config_digest IS NULL
			) OR (
				principal_snapshot_version = 'acp-principal/v1' AND
				length(project_id) BETWEEN 1 AND 256 AND
				project_id = btrim(project_id) AND project_id !~ '[[:cntrl:]]' AND
				principal_subject_id IS NOT NULL AND
				length(principal_subject_id) BETWEEN 1 AND 256 AND
				principal_subject_id = btrim(principal_subject_id) AND principal_subject_id !~ '[[:cntrl:]]' AND
				principal_actor_id IS NOT NULL AND
				length(principal_actor_id) BETWEEN 1 AND 256 AND
				principal_actor_id = btrim(principal_actor_id) AND principal_actor_id !~ '[[:cntrl:]]' AND
				principal_policy_revision IS NOT NULL AND
				length(principal_policy_revision) BETWEEN 1 AND 256 AND
				principal_policy_revision = btrim(principal_policy_revision) AND principal_policy_revision !~ '[[:cntrl:]]' AND
				principal_config_digest ~ '^sha256:[0-9a-f]{64}$'
			)
		  );
	`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		return fmt.Errorf("compile principal snapshot CHECK contract: %w", err)
	}
	var checkBound bool
	if err := tx.QueryRow(ctx, `
		SELECT count(*)=1
		FROM pg_constraint actual
		JOIN pg_constraint expected ON expected.conname=actual.conname
		WHERE actual.conrelid=to_regclass('run_intents')
		  AND expected.conrelid=to_regclass('pg_temp.acp_expected_run_intent_principal_snapshot')
		  AND actual.conname='run_intents_principal_snapshot_consistency'
		  AND actual.contype='c' AND expected.contype='c' AND actual.convalidated
		  AND pg_get_expr(actual.conbin,actual.conrelid,false)=
		      pg_get_expr(expected.conbin,expected.conrelid,false)
	`).Scan(&checkBound); err != nil {
		return fmt.Errorf("verify principal snapshot CHECK predicate: %w", err)
	}
	if !checkBound {
		return ErrSchemaDrift
	}

	expectedFunctions := map[string]string{
		"reject_run_intent_principal_snapshot_mutation": strings.TrimSpace("BEGIN\n    IF NEW.principal_snapshot_version IS DISTINCT FROM OLD.principal_snapshot_version\n        OR NEW.principal_subject_id IS DISTINCT FROM OLD.principal_subject_id\n        OR NEW.principal_actor_id IS DISTINCT FROM OLD.principal_actor_id\n        OR NEW.principal_policy_revision IS DISTINCT FROM OLD.principal_policy_revision\n        OR NEW.principal_config_digest IS DISTINCT FROM OLD.principal_config_digest THEN\n        RAISE EXCEPTION 'RunIntent principal snapshot is immutable';\n    END IF;\n    RETURN NEW;\nEND;"),
		"require_run_intent_principal_snapshot_for_dispatch": strings.TrimSpace("BEGIN\n    IF NEW.status = 'DISPATCHING' AND NEW.principal_snapshot_version IS NULL THEN\n        RAISE EXCEPTION 'RunIntent cannot dispatch without an immutable principal snapshot';\n    END IF;\n    RETURN NEW;\nEND;"),
	}
	for name, expected := range expectedFunctions {
		var body string
		err := tx.QueryRow(ctx, `
			SELECT p.prosrc FROM pg_proc p
			WHERE p.oid=to_regprocedure($1)
			  AND p.pronargs=0 AND p.prokind='f'
			  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
			  AND p.prorettype='pg_catalog.trigger'::regtype
			  AND p.provolatile='v' AND NOT p.prosecdef AND p.proconfig IS NULL
		`, name+"()").Scan(&body)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSchemaDrift
		}
		if err != nil {
			return fmt.Errorf("verify principal snapshot trigger function %s: %w", name, err)
		}
		if strings.TrimSpace(body) != expected {
			return ErrSchemaDrift
		}
	}

	var triggersBound bool
	if err := tx.QueryRow(ctx, `
		SELECT count(*)=2
		FROM pg_trigger t
		WHERE t.tgrelid=to_regclass('run_intents')
		  AND NOT t.tgisinternal AND t.tgenabled='O'
		  AND (
			(t.tgname='run_intent_principal_snapshot_immutable'
			 AND t.tgtype=19
			 AND t.tgfoid=to_regprocedure('reject_run_intent_principal_snapshot_mutation()')
			 AND (
				SELECT array_agg(a.attname::text ORDER BY k.ordinality)
				FROM unnest(t.tgattr::smallint[]) WITH ORDINALITY AS k(attnum,ordinality)
				JOIN pg_attribute a ON a.attrelid=t.tgrelid AND a.attnum=k.attnum
			 )=ARRAY['principal_snapshot_version','principal_subject_id','principal_actor_id','principal_policy_revision','principal_config_digest']::text[])
			OR
			(t.tgname='run_intent_dispatch_requires_principal_snapshot'
			 AND t.tgtype=23
			 AND t.tgfoid=to_regprocedure('require_run_intent_principal_snapshot_for_dispatch()')
			 AND (
				SELECT array_agg(a.attname::text ORDER BY k.ordinality)
				FROM unnest(t.tgattr::smallint[]) WITH ORDINALITY AS k(attnum,ordinality)
				JOIN pg_attribute a ON a.attrelid=t.tgrelid AND a.attnum=k.attnum
			 )=ARRAY['status']::text[])
		  )
	`).Scan(&triggersBound); err != nil {
		return fmt.Errorf("verify principal snapshot trigger bindings: %w", err)
	}
	if !triggersBound {
		return ErrSchemaDrift
	}
	return nil
}
