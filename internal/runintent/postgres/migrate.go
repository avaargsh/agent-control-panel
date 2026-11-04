package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	migrationLockID         int64 = 0x41435052554e
	initialMigrationVersion int64 = 1
	initialMigrationName          = "0001_run_intents_outbox_inbox.sql"
)

const conflictMigrationVersion int64 = 2
const conflictMigrationName = "0002_inbox_conflict_evidence.sql"

var (
	ErrSchemaDrift       = errors.New("RunIntent schema migration checksum or relation drift")
	ErrUnversionedSchema = errors.New("RunIntent schema exists without migration history")
)

// Migrate applies the embedded initial schema and its checksum ledger under
// one database transaction. A session advisory lock serializes concurrent
// service starts; schema objects and migration history commit or roll back
// together. Existing unversioned schemas are never silently adopted.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("postgres migration pool is nil")
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection for migrations: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("lock schema migrations: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", migrationLockID)
	}()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin schema migration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version BIGINT PRIMARY KEY CHECK (version > 0),
		name TEXT NOT NULL UNIQUE,
		checksum TEXT NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
		applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
	)`); err != nil {
		return fmt.Errorf("create schema migration ledger: %w", err)
	}

	source, err := migrations.FS.ReadFile(initialMigrationName)
	if err != nil {
		return fmt.Errorf("read embedded RunIntent migration: %w", err)
	}
	checksum := fmt.Sprintf("%x", sha256.Sum256(source))
	conflictSource, err := migrations.FS.ReadFile(conflictMigrationName)
	if err != nil {
		return fmt.Errorf("read embedded Inbox conflict migration: %w", err)
	}
	conflictChecksum := fmt.Sprintf("%x", sha256.Sum256(conflictSource))

	rows, err := tx.Query(ctx, "SELECT version, name, checksum FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("read schema migration history: %w", err)
	}
	var appliedVersion, conflictApplied bool
	for rows.Next() {
		var version int64
		var name, appliedChecksum string
		if err := rows.Scan(&version, &name, &appliedChecksum); err != nil {
			rows.Close()
			return fmt.Errorf("scan schema migration history: %w", err)
		}
		switch version {
		case initialMigrationVersion:
			if name != initialMigrationName || appliedChecksum != checksum || appliedVersion {
				rows.Close()
				return ErrSchemaDrift
			}
			appliedVersion = true
		case conflictMigrationVersion:
			if name != conflictMigrationName || appliedChecksum != conflictChecksum || conflictApplied {
				rows.Close()
				return ErrSchemaDrift
			}
			conflictApplied = true
		default:
			rows.Close()
			return ErrSchemaDrift
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate schema migration history: %w", err)
	}
	rows.Close()
	if conflictApplied && !appliedVersion {
		return ErrSchemaDrift
	}

	if appliedVersion {
		if err := verifyRunIntentSchema(ctx, tx); err != nil {
			return err
		}
		if err := ensureInboxConflictMigration(ctx, tx, conflictApplied, conflictSource, conflictChecksum); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit schema verification: %w", err)
		}
		return nil
	}

	var anySchemaExists bool
	if err := tx.QueryRow(ctx, `SELECT
		to_regclass('run_intents') IS NOT NULL
		OR to_regclass('outbox_events') IS NOT NULL
		OR to_regclass('inbox_events') IS NOT NULL
		OR to_regclass('inbox_aggregate_claims') IS NOT NULL
		OR to_regclass('inbox_cursors') IS NOT NULL
	`).Scan(&anySchemaExists); err != nil {
		return fmt.Errorf("inspect existing RunIntent schema: %w", err)
	}
	if anySchemaExists {
		return ErrUnversionedSchema
	}

	// The checked-in SQL file remains directly executable by psql in CI and
	// operator workflows. Remove only its explicit transaction wrapper because
	// this runner owns the transaction that also records the checksum.
	migrationSQL := strings.TrimSpace(string(source))
	migrationSQL = strings.TrimPrefix(migrationSQL, "BEGIN;")
	migrationSQL = strings.TrimSuffix(strings.TrimSpace(migrationSQL), "COMMIT;")
	migrationSQL = strings.TrimSpace(migrationSQL)
	if migrationSQL == "" || migrationSQL == strings.TrimSpace(string(source)) {
		return ErrSchemaDrift
	}
	if _, err := tx.Exec(ctx, migrationSQL, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("apply RunIntent migration %d: %w", initialMigrationVersion, err)
	}
	if err := verifyRunIntentSchema(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		"INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
		initialMigrationVersion, initialMigrationName, checksum,
	); err != nil {
		return fmt.Errorf("record RunIntent migration checksum: %w", err)
	}
	if err := ensureInboxConflictMigration(ctx, tx, false, conflictSource, conflictChecksum); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit RunIntent schema migration: %w", err)
	}
	return nil
}

// ensureInboxConflictMigration upgrades pre-existing v1 databases without
// altering the checksum-protected v1 migration. SQL, verification and ledger
// recording share the caller's advisory-locked migration transaction.
func ensureInboxConflictMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	if !applied {
		sql := strings.TrimSpace(string(source))
		sql = strings.TrimPrefix(sql, "BEGIN;")
		sql = strings.TrimSuffix(strings.TrimSpace(sql), "COMMIT;")
		sql = strings.TrimSpace(sql)
		if sql == "" || sql == strings.TrimSpace(string(source)) {
			return ErrSchemaDrift
		}
		if _, err := tx.Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol); err != nil {
			return fmt.Errorf("apply Inbox conflict migration v2: %w", err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			conflictMigrationVersion, conflictMigrationName, checksum); err != nil {
			return fmt.Errorf("record Inbox conflict migration v2: %w", err)
		}
	}

	var complete bool
	if err := tx.QueryRow(ctx, `
		SELECT to_regclass('inbox_event_conflicts') IS NOT NULL
	`).Scan(&complete); err != nil {
		return fmt.Errorf("verify Inbox conflict relation: %w", err)
	}
	if !complete {
		return ErrSchemaDrift
	}
	// Names alone are not enough. The archive's uniqueness scope must include
	// the conflict digest, and the original-event FK must bind both identity
	// columns; a same-name replacement must not be silently accepted.
	var constraints int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM (
			SELECT c.conname, c.contype, c.convalidated, c.confrelid,
				(SELECT array_agg(a.attname::text ORDER BY k.ordinality)
				 FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinality)
				 JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
				) AS local_columns,
				(SELECT array_agg(a.attname::text ORDER BY k.ordinality)
				 FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum,ordinality)
				 JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum
				) AS referenced_columns
			FROM pg_constraint c
			WHERE c.conrelid=to_regclass('inbox_event_conflicts')
		) AS c
		WHERE c.convalidated
		  AND (
			(c.conname='inbox_event_conflicts_pkey' AND c.contype='p'
			 AND c.local_columns=ARRAY['consumer_name','event_id','conflict_sha256'])
			OR
			(c.conname='inbox_event_conflicts_original_fkey' AND c.contype='f'
			 AND c.confrelid=to_regclass('inbox_events')
			 AND c.local_columns=ARRAY['consumer_name','event_id']
			 AND c.referenced_columns=ARRAY['consumer_name','event_id'])
		  )
	`).Scan(&constraints); err != nil {
		return fmt.Errorf("verify Inbox conflict constraint bindings: %w", err)
	}
	// pg_trigger.tgtype is an event bitmap: ROW=1 BEFORE=2 DELETE=8
	// UPDATE=16 TRUNCATE=32. Reject same-name triggers wired to another
	// event, to another function, or disabled for ordinary sessions.
	var triggers int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_trigger t
		WHERE t.tgrelid=to_regclass('inbox_event_conflicts')
		  AND NOT t.tgisinternal AND t.tgenabled='O'
		  AND t.tgfoid=to_regprocedure('reject_inbox_conflict_evidence_mutation()')
		  AND (
			(t.tgname='inbox_conflict_evidence_no_update_delete' AND t.tgtype=27)
			OR
			(t.tgname='inbox_conflict_evidence_no_truncate' AND t.tgtype=34)
		  )
	`).Scan(&triggers); err != nil {
		return fmt.Errorf("verify Inbox conflict trigger bindings: %w", err)
	}
	// A same-name CREATE OR REPLACE FUNCTION can change the trigger body
	// while preserving its OID and every pg_trigger binding. Check the
	// installed source against the immutable version-2 migration contract.
	var guardBody string
	err := tx.QueryRow(ctx, `
		SELECT p.prosrc FROM pg_proc p
		WHERE p.oid=to_regprocedure('reject_inbox_conflict_evidence_mutation()')
		  AND p.pronargs=0
		  AND p.prokind='f'
		  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
		  AND p.prorettype='pg_catalog.trigger'::regtype
		  AND p.provolatile='v'
		  AND NOT p.prosecdef
		  AND p.proconfig IS NULL
	`).Scan(&guardBody)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSchemaDrift
	}
	if err != nil {
		return fmt.Errorf("verify Inbox conflict trigger function: %w", err)
	}
	const expectedGuardBody = `BEGIN
    RAISE EXCEPTION 'inbox conflict evidence is append-only';
END;`
	if constraints != 2 || triggers != 2 ||
		strings.TrimSpace(guardBody) != expectedGuardBody {
		return ErrSchemaDrift
	}
	return nil
}

func verifyRunIntentSchema(ctx context.Context, tx pgx.Tx) error {
	var complete bool
	if err := tx.QueryRow(ctx, `SELECT
		to_regclass('run_intents') IS NOT NULL
		AND to_regclass('outbox_events') IS NOT NULL
		AND to_regclass('inbox_events') IS NOT NULL
		AND to_regclass('inbox_aggregate_claims') IS NOT NULL
		AND to_regclass('inbox_cursors') IS NOT NULL
	`).Scan(&complete); err != nil {
		return fmt.Errorf("verify RunIntent schema relations: %w", err)
	}
	if !complete {
		return ErrSchemaDrift
	}

	// A matching migration checksum proves which SQL was applied; it does not
	// prove that an operator has not since dropped a critical database guard.
	// Verify the constraints that enforce idempotency, lease/fence consistency,
	// state payload ownership, ordered Inbox identity and tenant-scoped claims.
	requiredConstraints := []string{
		"run_intents_pkey",
		"run_intents_idempotency_unique",
		"run_intents_lease_consistency",
		"run_intents_state_payload_consistency",
		"outbox_events_pkey",
		"outbox_aggregate_version_unique",
		"outbox_lease_consistency",
		"outbox_published_consistency",
		"inbox_events_pkey",
		"inbox_event_tenant_identity",
		"inbox_applied_consistency",
		"inbox_aggregate_claims_pkey",
		"inbox_aggregate_claims_consumer_name_event_id_key",
		"inbox_aggregate_claims_consumer_name_event_id_tenant_id_fkey",
		"inbox_cursors_pkey",
	}
	rows, err := tx.Query(ctx, `
		SELECT expected.constraint_name
		FROM unnest($1::text[]) AS expected(constraint_name)
		WHERE NOT EXISTS (
			SELECT 1
			FROM pg_constraint actual
			WHERE actual.conname = expected.constraint_name
			  AND actual.convalidated
			  AND actual.conrelid IN (
				to_regclass('run_intents'),
				to_regclass('outbox_events'),
				to_regclass('inbox_events'),
				to_regclass('inbox_aggregate_claims'),
				to_regclass('inbox_cursors')
			  )
		)
		ORDER BY expected.constraint_name
	`, requiredConstraints)
	if err != nil {
		return fmt.Errorf("verify RunIntent schema constraints: %w", err)
	}
	var missing []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("scan missing RunIntent schema constraint: %w", err)
		}
		missing = append(missing, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate missing RunIntent schema constraints: %w", err)
	}
	rows.Close()
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing or unvalidated constraints: %s", ErrSchemaDrift, strings.Join(missing, ", "))
	}
	return nil
}
