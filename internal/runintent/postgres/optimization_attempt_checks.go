package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// verifyOptimizationAttemptChecks rebuilds the reviewed v13 table's CHECK
// predicates in a disposable TEMP relation on the same PostgreSQL server.
// It compares column identity/types/NOT NULL/defaults and the complete\n// normalized expression multiset rather than
// trusting constraint names: CHECK (TRUE) under the original name is drift.
// The source is the checksum-pinned embedded migration, never a caller input.
func verifyOptimizationAttemptChecks(ctx context.Context, tx pgx.Tx, source []byte) error {
	const tableStart = "CREATE TABLE optimization_verification_attempts ("
	raw := string(source)
	if strings.Count(raw, tableStart) != 1 {
		return ErrSchemaDrift
	}
	tail := strings.SplitN(raw, tableStart, 2)[1]
	end := strings.Index(tail, "\n);")
	if end < 0 {
		return ErrSchemaDrift
	}
	expectedDDL := "CREATE TEMP TABLE acp_expected_optimization_checks (" +
		tail[:end] + "\n) ON COMMIT DROP"
	if _, err := tx.Exec(ctx, expectedDDL, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("compile expected optimization v13 CHECK constraints: %w", err)
	}
	if err := verifyOptimizationAttemptColumns(ctx, tx); err != nil {
		return err
	}
	// Compare the full ordered column contract against PostgreSQL's
	// interpretation of the pinned migration DDL. A same-name CHECK can
	// survive while a privileged operator drops NOT NULL, removes a
	// trusted timestamp default, or adds a consumed_at default.
	// All of these must fail closed on subsequent schema verification.
	var columnsEqual bool
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(
			(SELECT jsonb_agg(jsonb_build_array(
			   a.attnum, a.attname::text, a.atttypid::text, a.atttypmod,
			   a.attnotnull, a.attidentity::text, a.attgenerated::text,
			   a.attcollation::text, a.atthasmissing,
			   coalesce(pg_get_expr(d.adbin,d.adrelid,false),''))
			   ORDER BY a.attnum)
			 FROM pg_attribute a
			 LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
			 WHERE a.attrelid=to_regclass('optimization_verification_attempts')
			   AND a.attnum>0 AND NOT a.attisdropped)
			=
			(SELECT jsonb_agg(jsonb_build_array(
			   a.attnum, a.attname::text, a.atttypid::text, a.atttypmod,
			   a.attnotnull, a.attidentity::text, a.attgenerated::text,
			   a.attcollation::text, a.atthasmissing,
			   coalesce(pg_get_expr(d.adbin,d.adrelid,false),''))
			   ORDER BY a.attnum)
			 FROM pg_attribute a
			 LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
			 WHERE a.attrelid=to_regclass('pg_temp.acp_expected_optimization_checks')
			   AND a.attnum>0 AND NOT a.attisdropped),
			false)
	`).Scan(&columnsEqual); err != nil {
		return fmt.Errorf("inspect optimization v13 column metadata: %w", err)
	}
	if !columnsEqual {
		return ErrSchemaDrift
	}

	var equal bool
	if err := tx.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM pg_constraint c
		   WHERE c.conrelid=to_regclass('optimization_verification_attempts')
		     AND c.contype='c' AND (NOT c.convalidated OR c.connoinherit))=0
		  AND
		  (SELECT array_agg(pg_get_expr(c.conbin,c.conrelid,false)
		                    ORDER BY pg_get_expr(c.conbin,c.conrelid,false))
		   FROM pg_constraint c
		   WHERE c.conrelid=to_regclass('optimization_verification_attempts')
		     AND c.contype='c')
		  =
		  (SELECT array_agg(pg_get_expr(e.conbin,e.conrelid,false)
		                    ORDER BY pg_get_expr(e.conbin,e.conrelid,false))
		   FROM pg_constraint e
		   WHERE e.conrelid=to_regclass('pg_temp.acp_expected_optimization_checks')
		     AND e.contype='c')
	`).Scan(&equal); err != nil {
		return fmt.Errorf("inspect optimization v13 CHECK predicates: %w", err)
	}
	if !equal {
		return ErrSchemaDrift
	}
	return nil
}
