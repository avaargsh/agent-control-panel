package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/agent-control-panel/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationLockID int64 = 0x41435052554e

var (
	ErrSchemaDrift = errors.New("RunIntent schema migration checksum or relation drift")
	ErrUnversionedSchema = errors.New("RunIntent schema exists without migration history")
)

// Migrate applies the embedded initial schema once per database. A PostgreSQL
// advisory lock serializes concurrent service starts; the migration itself is
// transactional, so a failed migration can be safely retried.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return fmt.Errorf("postgres migration pool is nil")
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

	var schemaExists bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('run_intents') IS NOT NULL").Scan(&schemaExists); err != nil {
		return fmt.Errorf("inspect RunIntent schema: %w", err)
	}
	if schemaExists {
		return nil
	}

	source, err := migrations.FS.ReadFile("0001_run_intents_outbox_inbox.sql")
	if err != nil {
		return fmt.Errorf("read embedded RunIntent migration: %w", err)
	}
	if _, err := conn.Exec(ctx, string(source), pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("apply RunIntent migration: %w", err)
	}
	return nil
}
