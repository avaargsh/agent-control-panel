package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

func ensureAdmissionOriginMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		var partial bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass('run_intents')
			  AND attname IN ('admission_issuer','admission_external_subject','admission_client_id') AND NOT attisdropped
		) OR to_regprocedure('reject_run_intent_admission_origin_mutation()') IS NOT NULL
		  OR EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('run_intents')
			AND tgname='run_intent_admission_origin_immutable')`).Scan(&partial); err != nil {
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
			return fmt.Errorf("apply admission origin migration v12: %w", err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			admissionOriginMigrationVersion, admissionOriginMigrationName, checksum); err != nil {
			return err
		}
	}
	var columns bool
	if err := tx.QueryRow(ctx, `SELECT count(*)=3 FROM pg_attribute
		WHERE attrelid=to_regclass('run_intents')
		  AND attname IN ('admission_issuer','admission_external_subject','admission_client_id')
		  AND atttypid='pg_catalog.text'::regtype AND NOT attnotnull AND NOT atthasdef
		  AND NOT attisdropped AND attgenerated='' AND attidentity=''`).Scan(&columns); err != nil {
		return err
	}
	if !columns {
		return ErrSchemaDrift
	}

	// Compile the exact pinned predicate on the same server and compare
	// normalized expressions. A same-name no-op check is not sufficient.
	const marker = "ADD CONSTRAINT run_intents_admission_origin_consistency "
	start := strings.Index(string(source), marker)
	if start < 0 {
		return ErrSchemaDrift
	}
	predicate := strings.SplitN(string(source)[start+len("ADD "):], ";", 2)[0]
	stmt := `CREATE TEMP TABLE acp_expected_admission_origin (
		admission_issuer text, admission_external_subject text, admission_client_id text,
		execution_input bytea, principal_snapshot_version text,
		principal_subject_id text, principal_actor_id text,
		` + predicate + `
	) ON COMMIT DROP`
	if _, err := tx.Exec(ctx, stmt); err != nil {
		return err
	}
	var check bool
	if err := tx.QueryRow(ctx, `SELECT count(*)=1
		FROM pg_constraint actual JOIN pg_constraint expected ON expected.conname=actual.conname
		WHERE actual.conrelid=to_regclass('run_intents')
		  AND expected.conrelid=to_regclass('pg_temp.acp_expected_admission_origin')
		  AND actual.conname='run_intents_admission_origin_consistency'
		  AND actual.contype='c' AND actual.convalidated
		  AND pg_get_expr(actual.conbin,actual.conrelid,false)=pg_get_expr(expected.conbin,expected.conrelid,false)`).Scan(&check); err != nil {
		return err
	}
	if !check {
		return ErrSchemaDrift
	}
	var body string
	err := tx.QueryRow(ctx, `SELECT p.prosrc
		FROM pg_proc p JOIN pg_trigger t ON t.tgfoid=p.oid
		WHERE p.oid=to_regprocedure('reject_run_intent_admission_origin_mutation()')
		  AND p.pronargs=0 AND p.prokind='f' AND p.prorettype='pg_catalog.trigger'::regtype
		  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
		  AND p.provolatile='v' AND NOT p.prosecdef AND p.proconfig IS NULL
		  AND t.tgrelid=to_regclass('run_intents') AND t.tgname='run_intent_admission_origin_immutable'
		  AND NOT t.tgisinternal AND t.tgenabled='A' AND t.tgtype=19
		  AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr::text=''`).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSchemaDrift
	}
	if err != nil {
		return err
	}
	parts := strings.Split(string(source), "$origin$")
	if len(parts) != 3 || strings.TrimSpace(body) != strings.TrimSpace(parts[1]) {
		return ErrSchemaDrift
	}
	return nil
}
