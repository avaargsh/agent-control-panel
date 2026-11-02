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
	migrationLockID       int64 = 0x41435052554e
	initialMigrationVersion int64 = 1
	initialMigrationName        = "0001_run_intents_outbox_inbox.sql"
)

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

	rows, err := tx.Query(ctx, "SELECT version, name, checksum FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("read schema migration history: %w", err)
	}
	var appliedVersion bool
	for rows.Next() {
		var version int64
		var name, appliedChecksum string
		if err := rows.Scan(&version, &name, &appliedChecksum); err != nil {
			rows.Close()
			return fmt.Errorf("scan schema migration history: %w", err)
		}
		if version != initialMigrationVersion || name != initialMigrationName ||
			appliedChecksum != checksum || appliedVersion {
			rows.Close()
			return ErrSchemaDrift
		}
		appliedVersion = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate schema migration history: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close schema migration history: %w", err)
	}

	if appliedVersion {
		if err := verifyRunIntentSchema(ctx, tx); err != nil {
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
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit RunIntent schema migration: %w", err)
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
	return nil
}
