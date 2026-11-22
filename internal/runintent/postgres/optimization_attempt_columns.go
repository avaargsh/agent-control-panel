package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// verifyOptimizationAttemptColumns compares the *complete ordered column
// contract* on live v13 and on a temporary table compiled from checksum-
// pinned migration SQL by the same PostgreSQL server. CHECK predicates alone
// do not protect against dropping NOT NULL or substituting a default.
// A dropped/re-added or extra column is intentionally treated as drift.
func verifyOptimizationAttemptColumns(ctx context.Context, tx pgx.Tx) error {
	var identical bool
	err := tx.QueryRow(ctx, `
		WITH metadata AS (
			SELECT a.attrelid, a.attnum,
				jsonb_build_object(
					'name', a.attname,
					'type', a.atttypid::text,
					'type_modifier', a.atttypmod,
					'not_null', a.attnotnull,
					'collation', a.attcollation::text,
					'generated', a.attgenerated::text,
					'identity', a.attidentity::text,
					'has_default', a.atthasdef,
					'default', pg_get_expr(d.adbin,d.adrelid,false)
				) AS definition
			FROM pg_attribute a
			LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
			WHERE a.attrelid IN (
				to_regclass('optimization_verification_attempts'),
				to_regclass('pg_temp.acp_expected_optimization_checks')
			)
			AND a.attnum>0 AND NOT a.attisdropped
		)
		SELECT
			(SELECT jsonb_agg(definition ORDER BY attnum) FROM metadata
			  WHERE attrelid=to_regclass('optimization_verification_attempts'))
			=
			(SELECT jsonb_agg(definition ORDER BY attnum) FROM metadata
			  WHERE attrelid=to_regclass('pg_temp.acp_expected_optimization_checks'))
	`).Scan(&identical)
	if err != nil {
		return fmt.Errorf("verify optimization v13 column metadata: %w", err)
	}
	if !identical {
		return ErrSchemaDrift
	}
	return nil
}
