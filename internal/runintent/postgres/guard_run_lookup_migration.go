package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ensureGuardRunLookupMigration provides a bounded Guard read path without
// changing authority: duplicate accepted Run bindings remain nonunique and
// are rejected by GetGuardRunAuthority's LIMIT 2 check.
func ensureGuardRunLookupMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		var existing bool
		if err := tx.QueryRow(ctx,
			"SELECT to_regclass('run_intents_guard_accepted_runtime_lookup') IS NOT NULL").Scan(&existing); err != nil {
			return err
		}
		if existing {
			return ErrSchemaDrift
		}
		sql := strings.TrimSpace(string(source))
		if !strings.HasPrefix(sql, "BEGIN;") || !strings.HasSuffix(sql, "COMMIT;") {
			return ErrSchemaDrift
		}
		sql = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(sql, "BEGIN;"), "COMMIT;"))
		if _, err := tx.Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol); err != nil {
			return fmt.Errorf("apply Guard accepted-Run lookup index v14: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			guardRunLookupMigrationVersion, guardRunLookupMigrationName, checksum); err != nil {
			return fmt.Errorf("record Guard accepted-Run lookup index migration: %w", err)
		}
	}
	return verifyGuardRunLookupIndex(ctx, tx)
}

func verifyGuardRunLookupIndex(ctx context.Context, tx pgx.Tx) error {
	// Derive expected key order, INCLUDE columns and partial predicate from
	// a real PostgreSQL index on this exact server; index name alone, or a
	// predicate merely being nonnull, cannot establish the reviewed contract.
	if _, err := tx.Exec(ctx, `
CREATE TEMP TABLE acp_expected_guard_run_lookup (
	tenant_id text, runtime_run_id text, id uuid, request_digest text, status text
) ON COMMIT DROP;
CREATE INDEX acp_expected_guard_run_lookup_idx
	ON pg_temp.acp_expected_guard_run_lookup (tenant_id, runtime_run_id)
	INCLUDE (id, request_digest)
	WHERE status = 'ACCEPTED';
`, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("compile expected Guard Run lookup index: %w", err)
	}
	var valid bool
	if err := tx.QueryRow(ctx, `
SELECT count(*) = 1
  FROM pg_index actual
  JOIN pg_class idx ON idx.oid=actual.indexrelid
  JOIN pg_index expected ON expected.indrelid=to_regclass('pg_temp.acp_expected_guard_run_lookup')
 WHERE actual.indrelid=to_regclass('run_intents')
   AND idx.relname='run_intents_guard_accepted_runtime_lookup'
   AND idx.relnamespace=current_schema()::regnamespace
   AND actual.indisvalid AND actual.indisready
   AND NOT actual.indisunique AND NOT actual.indisprimary
   AND actual.indnkeyatts=2 AND actual.indnatts=4
   AND actual.indexprs IS NULL
   AND pg_get_indexdef(actual.indexrelid,1,false)=pg_get_indexdef(expected.indexrelid,1,false)
   AND pg_get_indexdef(actual.indexrelid,2,false)=pg_get_indexdef(expected.indexrelid,2,false)
   AND pg_get_indexdef(actual.indexrelid,3,false)=pg_get_indexdef(expected.indexrelid,3,false)
   AND pg_get_indexdef(actual.indexrelid,4,false)=pg_get_indexdef(expected.indexrelid,4,false)
   AND pg_get_expr(actual.indpred,actual.indrelid,false)=
       pg_get_expr(expected.indpred,expected.indrelid,false)
`).Scan(&valid); err != nil {
		return fmt.Errorf("verify guarded Run lookup index catalog: %w", err)
	}
	if !valid {
		return ErrSchemaDrift
	}
	return nil
}
