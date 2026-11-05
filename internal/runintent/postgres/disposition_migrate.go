package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ensureDLQDispositionMigration is additive to the checksum-pinned v1/v2
// chain. It owns only the version-3 schema, not broker I/O, replay approval,
// or production database-role provisioning.
func ensureDLQDispositionMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		var existing bool
		if err := tx.QueryRow(ctx, `
			SELECT to_regclass('dlq_dispositions') IS NOT NULL
			    OR to_regprocedure('reject_dlq_disposition_mutation()') IS NOT NULL
		`).Scan(&existing); err != nil {
			return fmt.Errorf("inspect preexisting DLQ disposition schema: %w", err)
		}
		if existing {
			return ErrUnversionedSchema
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
		if err := verifyDLQDispositionSchema(ctx, tx, source); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			dispositionMigrationVersion, dispositionMigrationName, checksum); err != nil {
			return fmt.Errorf("record DLQ disposition migration v3: %w", err)
		}
		return nil
	}
	return verifyDLQDispositionSchema(ctx, tx, source)
}

func verifyDLQDispositionSchema(ctx context.Context, tx pgx.Tx, source []byte) error {
	// A same-named table or function is insufficient: check real relation
	// kind, ownership scope and the exact ordered immutable delivery key.
	var present bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_class r
			WHERE r.oid=to_regclass('dlq_dispositions')
			  AND r.relkind='r' AND r.relpersistence='p'
			  AND r.relnamespace=current_schema()::regnamespace
		)
	`).Scan(&present); err != nil {
		return fmt.Errorf("inspect DLQ disposition relation: %w", err)
	}
	if !present {
		return ErrSchemaDrift
	}
	var primaryKey int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_constraint c
		WHERE c.conrelid=to_regclass('dlq_dispositions')
		  AND c.contype='p' AND c.convalidated
		  AND (
			SELECT array_agg(a.attname::text ORDER BY k.ordinality)
			FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinality)
			JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
		  )=ARRAY['source_stream','source_consumer','source_sequence']::text[]
	`).Scan(&primaryKey)
	if err != nil {
		return fmt.Errorf("verify DLQ disposition immutable key: %w", err)
	}
	if primaryKey != 1 {
		return ErrSchemaDrift
	}

	// Must bind both native triggers to this relation, all UPDATE columns
	// (tgattr empty), no WHEN predicate (tgqual NULL), and the correct
	// operation bitmap. A same-named disabled/conditional/narrowed trigger
	// or trigger wired to another function must not be trusted.
	var guards int
	err = tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_trigger t
		WHERE t.tgrelid=to_regclass('dlq_dispositions')
		  AND NOT t.tgisinternal AND t.tgenabled='O'
		  AND t.tgattr::text='' AND t.tgqual IS NULL
		  AND t.tgfoid=to_regprocedure('reject_dlq_disposition_mutation()')
		  AND (
			(t.tgname='dlq_disposition_no_unsafe_update_delete' AND t.tgtype=27)
			OR
			(t.tgname='dlq_disposition_no_truncate' AND t.tgtype=34)
		  )
	`).Scan(&guards)
	if err != nil {
		return fmt.Errorf("verify DLQ disposition trigger bindings: %w", err)
	}
	if guards != 2 {
		return ErrSchemaDrift
	}

	// Compare the actual PL/pgSQL body to the reviewed, checksum-pinned
	// migration. CREATE OR REPLACE can change prosrc without changing OIDs.
	const functionMarker = "RETURNS trigger LANGUAGE plpgsql AS $$"
	sqlText := string(source)
	if strings.Count(sqlText, functionMarker) != 1 {
		return ErrSchemaDrift
	}
	from := strings.Index(sqlText, functionMarker) + len(functionMarker)
	to := strings.Index(sqlText[from:], "$$;")
	if to < 0 {
		return ErrSchemaDrift
	}
	wantBody := strings.TrimSpace(sqlText[from : from+to])
	var actualBody string
	err = tx.QueryRow(ctx, `
		SELECT p.prosrc FROM pg_proc p
		WHERE p.oid=to_regprocedure('reject_dlq_disposition_mutation()')
		  AND p.pronargs=0 AND p.prokind='f'
		  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
		  AND p.prorettype='pg_catalog.trigger'::regtype
		  AND p.provolatile='v' AND NOT p.prosecdef AND p.proconfig IS NULL
	`).Scan(&actualBody)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSchemaDrift
	}
	if err != nil {
		return fmt.Errorf("verify DLQ disposition guard function: %w", err)
	}
	if strings.TrimSpace(actualBody) != wantBody {
		return ErrSchemaDrift
	}

	// No role grant is conferred by migration. In particular, PUBLIC must
	// never regain table access or EXECUTE on the mutation guard through
	// later operator grants. Compare native ACL entries, not names/strings.
	var publicGrants bool
	err = tx.QueryRow(ctx, `
		SELECT
			EXISTS (
				SELECT 1
				FROM pg_class c,
				     LATERAL aclexplode(coalesce(c.relacl, acldefault('r',c.relowner))) grant_entry
				WHERE c.oid=to_regclass('dlq_dispositions')
				  AND grant_entry.grantee=0
			)
			OR EXISTS (
				SELECT 1
				FROM pg_proc p,
				     LATERAL aclexplode(coalesce(p.proacl, acldefault('f',p.proowner))) grant_entry
				WHERE p.oid=to_regprocedure('reject_dlq_disposition_mutation()')
				  AND grant_entry.grantee=0
			)
	`).Scan(&publicGrants)
	if err != nil {
		return fmt.Errorf("verify DLQ disposition PUBLIC privilege boundary: %w", err)
	}
	if publicGrants {
		return ErrSchemaDrift
	}

	// PostgreSQL compiles the reviewed v3 CHECK expressions for exact
	// catalog comparison. Named table predicates come from the pinned SQL;
	// PostgreSQL-generated column CHECK names use their frozen v3 expressions.
	// Merely checking the two named table constraints missed digest and reason
	// tampering (including a same-name CHECK(TRUE) replacement).
	if _, err := tx.Exec(ctx,
		"CREATE TEMP TABLE acp_expected_dlq_checks (LIKE dlq_dispositions) ON COMMIT DROP"); err != nil {
		return fmt.Errorf("compile pinned v3 CHECK relation: %w", err)
	}
	checks := []struct {
		name      string
		predicate string
	}{
		{name: "dlq_published_consistency"},
		{name: "dlq_requires_attempt"},
		{name: "dlq_dispositions_delivery_sha256_check", predicate: "delivery_sha256 ~ '^[a-f0-9]{64}		if _, err := tx.Exec(ctx, fmt.Sprintf(
			"ALTER TABLE pg_temp.acp_expected_dlq_checks ADD CONSTRAINT %s CHECK (%s)",
			name, predicate)); err != nil {
			return fmt.Errorf("compile pinned disposition CHECK %s: %w", name, err)
		}
		var matches bool
		err = tx.QueryRow(ctx, `
			SELECT pg_get_expr(actual.conbin, actual.conrelid, false) =
			       pg_get_expr(expected.conbin, expected.conrelid, false)
			FROM pg_constraint actual
			JOIN pg_constraint expected ON actual.conname=expected.conname
			WHERE actual.conrelid=to_regclass('dlq_dispositions')
			  AND expected.conrelid=to_regclass('pg_temp.acp_expected_dlq_checks')
			  AND actual.conname=$1
			  AND actual.contype='c' AND expected.contype='c'
			  AND actual.convalidated
		`, name).Scan(&matches)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !matches {
			return fmt.Errorf("%w: changed predicate for dlq_dispositions.%s", ErrSchemaDrift, name)
		}
		if err != nil {
			return fmt.Errorf("verify DLQ disposition CHECK %s: %w", name, err)
		}
	}
	return nil
}
"},
		{name: "dlq_dispositions_reason_check", predicate: "reason IN ('EVENT_ID_CONFLICT','INBOX_QUARANTINED')"},
	}
	for _, check := range checks {
		name, predicate := check.name, check.predicate
		if predicate == "" {
			var err error
			predicate, err = pinnedMigrationCheckPredicate(sqlText, name)
			if err != nil {
				return fmt.Errorf("%w: invalid pinned predicate for %s", ErrSchemaDrift, name)
			}
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(
			"ALTER TABLE pg_temp.acp_expected_dlq_checks ADD CONSTRAINT %s CHECK (%s)",
			name, predicate)); err != nil {
			return fmt.Errorf("compile pinned disposition CHECK %s: %w", name, err)
		}
		var matches bool
		err = tx.QueryRow(ctx, `
			SELECT pg_get_expr(actual.conbin, actual.conrelid, false) =
			       pg_get_expr(expected.conbin, expected.conrelid, false)
			FROM pg_constraint actual
			JOIN pg_constraint expected ON actual.conname=expected.conname
			WHERE actual.conrelid=to_regclass('dlq_dispositions')
			  AND expected.conrelid=to_regclass('pg_temp.acp_expected_dlq_checks')
			  AND actual.conname=$1
			  AND actual.contype='c' AND expected.contype='c'
			  AND actual.convalidated
		`, name).Scan(&matches)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !matches {
			return fmt.Errorf("%w: changed predicate for dlq_dispositions.%s", ErrSchemaDrift, name)
		}
		if err != nil {
			return fmt.Errorf("verify DLQ disposition CHECK %s: %w", name, err)
		}
	}
	return nil
}
