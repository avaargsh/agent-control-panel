package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// verifyOptimizationAttemptChecks rebuilds the reviewed v13 table's CHECK
// predicates in a disposable TEMP relation on the same PostgreSQL server.
// It compares the full column contract and normalized CHECK expressions
// against the source migration, not merely their names. CHECK (TRUE) under
// the original name is drift.
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
