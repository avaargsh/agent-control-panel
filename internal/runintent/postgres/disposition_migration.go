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
	// Competing Draft v3 implementations used the same migration version but
	// different journal relations. A legacy unversioned relation can survive
	// an out-of-band or interrupted rollout; never create a second authority
	// beside it, even if no v3 checksum was recorded.
	var competingJournal bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_class c
		WHERE c.relnamespace=current_schema()::regnamespace
		  AND c.relname='dlq_dispositions'
	)`).Scan(&competingJournal); err != nil {
		return fmt.Errorf("inspect competing v3 disposition relation: %w", err)
	}
	if competingJournal {
		return ErrSchemaDrift
	}
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
	// Evidence must live in the owned schema as an ordinary durable table.
	// An UNLOGGED relation cannot satisfy post-crash DLQ recovery.
	var complete bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_class r
			WHERE r.oid=to_regclass('inbox_dlq_dispositions')
			  AND r.relkind='r' AND r.relpersistence='p'
			  AND r.relnamespace=current_schema()::regnamespace
		)
	`).Scan(&complete); err != nil {
		return fmt.Errorf("verify v3 disposition relation: %w", err)
	}
	if !complete {
		return ErrSchemaDrift
	}
	// Every immutable source, tenant and evidence attribute must retain its
	// reviewed type and NOT NULL fence. A checksum-only check misses post-
	// migration DROP NOT NULL or ALTER COLUMN TYPE tampering.
	var columnsBound bool
	if err := tx.QueryRow(ctx, `
		WITH expected(name, typ) AS (
			VALUES
			  ('tenant_id', 'pg_catalog.text'::regtype),
			  ('consumer_name', 'pg_catalog.text'::regtype),
			  ('source_stream', 'pg_catalog.text'::regtype),
			  ('source_consumer', 'pg_catalog.text'::regtype),
			  ('source_sequence', 'pg_catalog.int8'::regtype),
			  ('event_id', 'pg_catalog.uuid'::regtype),
			  ('delivery_sha256', 'pg_catalog.text'::regtype),
			  ('reason', 'pg_catalog.text'::regtype),
			  ('dlq_stream', 'pg_catalog.text'::regtype),
			  ('dlq_subject', 'pg_catalog.text'::regtype),
			  ('evidence', 'pg_catalog.bytea'::regtype),
			  ('publish_started', 'pg_catalog.bool'::regtype),
			  ('published', 'pg_catalog.bool'::regtype),
			  ('created_at', 'pg_catalog.timestamptz'::regtype)
		)
		SELECT count(*)=(SELECT count(*) FROM expected)
		FROM expected e
		JOIN pg_attribute a ON a.attrelid=to_regclass('inbox_dlq_dispositions')
		  AND a.attname=e.name AND a.atttypid=e.typ
		  AND a.attnotnull AND NOT a.attisdropped
	`).Scan(&columnsBound); err != nil {
		return fmt.Errorf("verify immutable disposition column bindings: %w", err)
	}
	if !columnsBound {
		return ErrSchemaDrift
	}
	// Default-value drift can forge a started publication attempt without
	// recording an actual attempt, or fabricate a fixed evidence timestamp.
	// Keep the nullable publication timestamp type and absence of a default.
	var stateDefaultsBound bool
	if err := tx.QueryRow(ctx, `
		WITH expected(name, typ, required, default_sql) AS (
			VALUES
			  ('publish_started', 'pg_catalog.bool'::regtype, true, 'false'::text),
			  ('published', 'pg_catalog.bool'::regtype, true, 'false'::text),
			  ('created_at', 'pg_catalog.timestamptz'::regtype, true, 'clock_timestamp()'::text),
			  ('published_at', 'pg_catalog.timestamptz'::regtype, false, NULL::text)
		)
		SELECT count(*)=(SELECT count(*) FROM expected)
		FROM expected e
		JOIN pg_attribute a ON a.attrelid=to_regclass('inbox_dlq_dispositions')
		  AND a.attname=e.name AND a.atttypid=e.typ
		  AND a.attnotnull=e.required AND NOT a.attisdropped
		LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
		WHERE (e.default_sql IS NULL AND d.oid IS NULL)
		   OR (e.default_sql IS NOT NULL
		       AND pg_get_expr(d.adbin,d.adrelid,false)=e.default_sql)
	`).Scan(&stateDefaultsBound); err != nil {
		return fmt.Errorf("verify disposition publication state defaults: %w", err)
	}
	if !stateDefaultsBound {
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

	// Public grants bypass the isolated worker role/tenant evidence fence.
	// Verify both relation and trigger function, including implicit defaults.
	var publicGrants bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_class c,
			     LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) e
			WHERE c.oid=to_regclass('inbox_dlq_dispositions') AND e.grantee=0
		) OR EXISTS (
			SELECT 1 FROM pg_proc p,
			     LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) e
			WHERE p.oid=to_regprocedure('reject_inbox_dlq_disposition_mutation()')
			  AND e.grantee=0
		)
	`).Scan(&publicGrants)
	if err != nil {
		return fmt.Errorf("verify disposition PUBLIC grants: %w", err)
	}
	if publicGrants {
		return ErrSchemaDrift
	}

	// Compile each pinned CHECK on a temporary copy using *this PostgreSQL*
	// server and compare pg_get_expr. Constraint names alone are insufficient.
	_, err = tx.Exec(ctx, "CREATE TEMP TABLE acp_expected_dlq_checks (LIKE inbox_dlq_dispositions) ON COMMIT DROP")
	if err != nil {
		return fmt.Errorf("create expected disposition predicate relation: %w", err)
	}
	checks := []struct {
		name      string
		predicate string
	}{
		{name: "inbox_dlq_published_at_check"},
		{name: "inbox_dlq_requires_attempt"},
		{name: "inbox_dlq_dispositions_tenant_id_check", predicate: "tenant_id <> '' AND tenant_id = btrim(tenant_id)"},
		{name: "inbox_dlq_dispositions_consumer_name_check", predicate: "consumer_name <> '' AND consumer_name = btrim(consumer_name)"},
		{name: "inbox_dlq_dispositions_source_stream_check", predicate: "source_stream <> ''"},
		{name: "inbox_dlq_dispositions_source_consumer_check", predicate: "source_consumer <> ''"},
		{name: "inbox_dlq_dispositions_source_sequence_check", predicate: "source_sequence > 0"},
		{name: "inbox_dlq_dispositions_delivery_sha256_check", predicate: "delivery_sha256 ~ '^[a-f0-9]{64}$'"},
		{name: "inbox_dlq_dispositions_reason_check", predicate: "reason IN ('EVENT_ID_CONFLICT','INBOX_QUARANTINED')"},
		{name: "inbox_dlq_dispositions_dlq_stream_check", predicate: "dlq_stream <> ''"},
		{name: "inbox_dlq_dispositions_dlq_subject_check", predicate: "dlq_subject <> ''"},
		{name: "inbox_dlq_dispositions_evidence_check", predicate: "octet_length(evidence) > 0"},
	}
	for _, check := range checks {
		name, predicate := check.name, check.predicate
		if predicate == "" {
			var err error
			predicate, err = pinnedMigrationCheckPredicate(migrationSQL, name)
			if err != nil {
				return fmt.Errorf("%w: missing pinned v3 CHECK %s", ErrSchemaDrift, name)
			}
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
