package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

const (
	dispositionMigrationVersion int64 = 3
	dispositionMigrationName          = "0003_inbox_dlq_dispositions.sql"
)

// ensureInboxDLQDispositionMigration is additive and uses the same locked,
// single-transaction checksum ledger as v1/v2. A preexisting unrecorded table
// is never silently adopted, and failed verification rolls back the upgrade.
func ensureInboxDLQDispositionMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT to_regclass('inbox_dlq_dispositions') IS NOT NULL").Scan(&exists); err != nil {
			return fmt.Errorf("inspect preexisting v3 disposition journal: %w", err)
		}
		if exists {
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
			return fmt.Errorf("apply DLQ disposition migration v3: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			dispositionMigrationVersion, dispositionMigrationName, checksum); err != nil {
			return fmt.Errorf("record DLQ disposition migration v3: %w", err)
		}
	}
	return verifyInboxDLQDispositionSchema(ctx, tx, source)
}

// verifyInboxDLQDispositionSchema validates the live catalog, not merely the
// recorded migration checksum. A malicious same-named CHECK(TRUE), disabled
// trigger, narrowed UPDATE OF trigger or changed guard-function body must
// reject startup. This does NOT protect against privileged drift after startup.
func verifyInboxDLQDispositionSchema(ctx context.Context, tx pgx.Tx, source []byte) error {
	var complete bool
	if err := tx.QueryRow(ctx,
		"SELECT to_regclass('inbox_dlq_dispositions') IS NOT NULL").Scan(&complete); err != nil {
		return fmt.Errorf("verify v3 disposition relation: %w", err)
	}
	if !complete {
		return ErrSchemaDrift
	}
	var pk int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_constraint c
		WHERE c.conrelid=to_regclass('inbox_dlq_dispositions')
		  AND c.contype='p' AND c.convalidated
		  AND (
		    SELECT array_agg(a.attname::text ORDER BY k.ordinality)
		    FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinality)
		    JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
		  )=ARRAY['source_stream','source_consumer','source_sequence']::text[]
	`).Scan(&pk); err != nil {
		return fmt.Errorf("verify disposition primary key: %w", err)
	}
	if pk != 1 {
		return ErrSchemaDrift
	}
	// ROW=1 BEFORE=2 DELETE=8 UPDATE=16; statement BEFORE TRUNCATE=34.
	// A row UPDATE OF column list is encoded in tgattr, and WHEN in tgqual.
	var guards int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_trigger t
		WHERE t.tgrelid=to_regclass('inbox_dlq_dispositions')
		  AND NOT t.tgisinternal AND t.tgenabled='O'
		  AND t.tgattr::text='' AND t.tgqual IS NULL
		  AND t.tgfoid=to_regprocedure('reject_inbox_dlq_disposition_mutation()')
		  AND (
		    (t.tgname='inbox_dlq_no_unsafe_update_delete' AND t.tgtype=27)
		    OR
		    (t.tgname='inbox_dlq_no_truncate' AND t.tgtype=34)
		  )
	`).Scan(&guards); err != nil {
		return fmt.Errorf("verify disposition guard triggers: %w", err)
	}
	if guards != 2 {
		return ErrSchemaDrift
	}

	// The function must match the exactly checksum-pinned v3 migration
	// source, including its definer/security characteristics.
	const marker = "CREATE FUNCTION reject_inbox_dlq_disposition_mutation()"
	migrationSQL := string(source)
	if strings.Count(migrationSQL, marker) != 1 {
		return ErrSchemaDrift
	}
	guardStart := strings.Index(migrationSQL, marker)
	asStart := strings.Index(migrationSQL[guardStart:], "AS $$")
	if asStart < 0 {
		return ErrSchemaDrift
	}
	bodyStart := guardStart + asStart + len("AS $$")
	bodyEnd := strings.Index(migrationSQL[bodyStart:], "$$;")
	if bodyEnd < 0 {
		return ErrSchemaDrift
	}
	expectedSource := strings.TrimSpace(migrationSQL[bodyStart : bodyStart+bodyEnd])

	var actualSource string
	err := tx.QueryRow(ctx, `
		SELECT p.prosrc FROM pg_proc p
		WHERE p.oid=to_regprocedure('reject_inbox_dlq_disposition_mutation()')
		  AND p.pronargs=0 AND p.prokind='f'
		  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
		  AND p.prorettype='pg_catalog.trigger'::regtype
		  AND p.provolatile='v' AND NOT p.prosecdef AND p.proconfig IS NULL
	`).Scan(&actualSource)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSchemaDrift
	}
	if err != nil {
		return fmt.Errorf("verify disposition guard function: %w", err)
	}
	if strings.TrimSpace(actualSource) != expectedSource {
		return ErrSchemaDrift
	}

	// Compile each pinned CHECK on a temporary copy using *this PostgreSQL*
	// server and compare pg_get_expr. Constraint names alone are insufficient.
	_, err = tx.Exec(ctx, "CREATE TEMP TABLE acp_expected_dlq_checks (LIKE inbox_dlq_dispositions) ON COMMIT DROP")
	if err != nil {
		return fmt.Errorf("create expected disposition predicate relation: %w", err)
	}
	for _, name := range []string{"inbox_dlq_published_at_check", "inbox_dlq_requires_attempt"} {
		predicate, err := pinnedMigrationCheckPredicate(migrationSQL, name)
		if err != nil {
			return fmt.Errorf("%w: missing pinned v3 CHECK %s", ErrSchemaDrift, name)
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(
			"ALTER TABLE pg_temp.acp_expected_dlq_checks ADD CONSTRAINT %s CHECK (%s)",
			name, predicate)); err != nil {
			return fmt.Errorf("compile expected v3 CHECK %s: %w", name, err)
		}
		var equal bool
		err = tx.QueryRow(ctx, `
			SELECT pg_get_expr(actual.conbin,actual.conrelid,false)=
			       pg_get_expr(expected.conbin,expected.conrelid,false)
			FROM pg_constraint actual
			JOIN pg_constraint expected ON actual.conname=expected.conname
			WHERE actual.conrelid=to_regclass('inbox_dlq_dispositions')
			  AND expected.conrelid=to_regclass('pg_temp.acp_expected_dlq_checks')
			  AND actual.conname=$1
			  AND actual.contype='c' AND expected.contype='c'
			  AND actual.convalidated
		`, name).Scan(&equal)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !equal {
			return fmt.Errorf("%w: changed v3 CHECK %s", ErrSchemaDrift, name)
		}
		if err != nil {
			return fmt.Errorf("verify v3 CHECK %s: %w", name, err)
		}
	}

	// Keep production migration ownership explicit: the actual runtime
	// database role remains external and must receive column-scoped grants.
	return nil
}
