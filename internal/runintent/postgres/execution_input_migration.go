package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

func ensureExecutionInputMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		var partial bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass('run_intents')
			  AND attname='execution_input' AND NOT attisdropped
		) OR to_regprocedure('reject_run_intent_execution_input_mutation()') IS NOT NULL
		  OR EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('run_intents')
			AND tgname='run_intent_execution_input_immutable')`).Scan(&partial); err != nil {
			return fmt.Errorf("inspect execution input migration: %w", err)
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
			return fmt.Errorf("apply execution input migration v10: %w", err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			executionInputMigrationVersion, executionInputMigrationName, checksum); err != nil {
			return fmt.Errorf("record execution input migration v10: %w", err)
		}
	}

	var columnBound bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass('run_intents')
		AND attname='execution_input' AND atttypid='pg_catalog.bytea'::regtype
		AND NOT attnotnull AND NOT atthasdef AND NOT attisdropped
	)`).Scan(&columnBound); err != nil {
		return err
	}
	if !columnBound {
		return ErrSchemaDrift
	}
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE acp_expected_execution_input (
		execution_input bytea,
		CONSTRAINT run_intents_execution_input_size
			CHECK (execution_input IS NULL OR octet_length(execution_input) BETWEEN 2 AND 262144)
	) ON COMMIT DROP`); err != nil {
		return err
	}
	var checkBound bool
	if err := tx.QueryRow(ctx, `SELECT count(*)=1
		FROM pg_constraint actual JOIN pg_constraint expected ON expected.conname=actual.conname
		WHERE actual.conrelid=to_regclass('run_intents')
		  AND expected.conrelid=to_regclass('pg_temp.acp_expected_execution_input')
		  AND actual.conname='run_intents_execution_input_size'
		  AND actual.contype='c' AND actual.convalidated
		  AND pg_get_expr(actual.conbin,actual.conrelid,false)=
		      pg_get_expr(expected.conbin,expected.conrelid,false)`).Scan(&checkBound); err != nil {
		return err
	}
	if !checkBound {
		return ErrSchemaDrift
	}
	var body string
	err := tx.QueryRow(ctx, `SELECT p.prosrc FROM pg_proc p
		WHERE p.oid=to_regprocedure('reject_run_intent_execution_input_mutation()')
		  AND p.pronargs=0 AND p.prokind='f'
		  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
		  AND p.prorettype='pg_catalog.trigger'::regtype
		  AND p.provolatile='v' AND NOT p.prosecdef AND p.proconfig IS NULL`).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSchemaDrift
	}
	if err != nil {
		return err
	}
	// Compare the function body against the checksum-pinned migration, not
	// just the object name. A replaced/no-op trigger must prevent startup.
	parts := strings.Split(string(source), "$input$")
	if len(parts) != 3 || strings.TrimSpace(body) != strings.TrimSpace(parts[1]) {
		return ErrSchemaDrift
	}
	var triggerBound bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_trigger
		WHERE tgrelid=to_regclass('run_intents')
		  AND tgname='run_intent_execution_input_immutable'
		  AND NOT tgisinternal AND tgenabled='O' AND tgtype=19
		  AND tgfoid=to_regprocedure('reject_run_intent_execution_input_mutation()')
		  AND tgqual IS NULL AND tgnargs=0 AND tgattr::text=''
	)`).Scan(&triggerBound); err != nil {
		return err
	}
	if !triggerBound {
		return ErrSchemaDrift
	}
	return nil
}
