package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/domain"
)

const runColumns = `id, tenant_id, agent_id, release_id, session_id, status, input::text, version, failure, created_at, updated_at`

type Store struct{ db *sql.DB }

func New(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) CreateRun(ctx context.Context, run domain.Run, key, requestHash string) (domain.Run, bool, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return domain.Run{}, false, fmt.Errorf("begin create run: %w", err)
	}
	defer tx.Rollback()

	var claimedID string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO idempotency_records (tenant_id, operation, idempotency_key, request_hash, resource_id)
		VALUES ($1, 'POST:/api/v1/runs', $2, $3, $4)
		ON CONFLICT (tenant_id, operation, idempotency_key) DO NOTHING
		RETURNING resource_id`, run.TenantID, key, requestHash, run.ID).Scan(&claimedID)
	if errors.Is(err, sql.ErrNoRows) {
		var previousHash, previousID string
		if err := tx.QueryRowContext(ctx, `SELECT request_hash, resource_id FROM idempotency_records WHERE tenant_id=$1 AND operation='POST:/api/v1/runs' AND idempotency_key=$2 FOR UPDATE`, run.TenantID, key).Scan(&previousHash, &previousID); err != nil {
			return domain.Run{}, false, fmt.Errorf("read idempotency record: %w", err)
		}
		if previousHash != requestHash {
			return domain.Run{}, false, domain.ErrIdempotencyConflict
		}
		previous, err := scanRun(tx.QueryRowContext(ctx, `SELECT `+runColumns+` FROM runs WHERE id=$1 AND tenant_id=$2`, previousID, run.TenantID))
		if err != nil {
			return domain.Run{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return domain.Run{}, false, fmt.Errorf("commit idempotent replay: %w", err)
		}
		return previous, false, nil
	}
	if err != nil {
		return domain.Run{}, false, fmt.Errorf("claim idempotency key: %w", err)
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO sessions (id, tenant_id, agent_id) VALUES ($1,$2,$3) ON CONFLICT (id) DO NOTHING`, run.SessionID, run.TenantID, run.AgentID)
	if err != nil {
		return domain.Run{}, false, fmt.Errorf("create session: %w", err)
	}
	var sessionTenant, sessionAgent string
	if err := tx.QueryRowContext(ctx, `SELECT tenant_id, agent_id FROM sessions WHERE id=$1`, run.SessionID).Scan(&sessionTenant, &sessionAgent); err != nil {
		return domain.Run{}, false, fmt.Errorf("verify session: %w", err)
	}
	if sessionTenant != run.TenantID || sessionAgent != run.AgentID {
		return domain.Run{}, false, fmt.Errorf("%w: session identity belongs to another tenant or agent", domain.ErrInvalidInput)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO runs (id, tenant_id, agent_id, release_id, session_id, status, input, version, failure, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,NULL,$9,$10)`,
		run.ID, run.TenantID, run.AgentID, run.ReleaseID, run.SessionID, string(run.Status), []byte(run.Input), run.Version, run.CreatedAt, run.UpdatedAt)
	if err != nil {
		return domain.Run{}, false, fmt.Errorf("persist run: %w", err)
	}
	if err := insertOutbox(ctx, tx, "RunCreated", run, run.CreatedAt); err != nil {
		return domain.Run{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return domain.Run{}, false, fmt.Errorf("commit create run: %w", err)
	}
	return run, true, nil
}

func (s *Store) GetRun(ctx context.Context, tenantID, runID string) (domain.Run, error) {
	run, err := scanRun(s.db.QueryRowContext(ctx, `SELECT `+runColumns+` FROM runs WHERE id=$1 AND tenant_id=$2`, runID, tenantID))
	if err != nil {
		return domain.Run{}, err
	}
	return run, nil
}

func (s *Store) TransitionRun(ctx context.Context, tenantID, runID string, expectedVersion int64, target domain.RunStatus, reason string, at time.Time) (domain.Run, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return domain.Run{}, fmt.Errorf("begin transition: %w", err)
	}
	defer tx.Rollback()

	run, err := scanRun(tx.QueryRowContext(ctx, `SELECT `+runColumns+` FROM runs WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, runID, tenantID))
	if err != nil {
		return domain.Run{}, err
	}
	if run.Version != expectedVersion {
		return domain.Run{}, domain.ErrVersionConflict
	}
	updated, err := run.Transition(target, reason, at)
	if err != nil {
		return domain.Run{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE runs SET status=$1, version=$2, failure=NULLIF($3,''), updated_at=$4 WHERE id=$5 AND tenant_id=$6 AND version=$7`, string(updated.Status), updated.Version, updated.Failure, updated.UpdatedAt, updated.ID, updated.TenantID, expectedVersion)
	if err != nil {
		return domain.Run{}, fmt.Errorf("update run: %w", err)
	}
	if err := insertOutbox(ctx, tx, "RunStatusChanged", updated, updated.UpdatedAt); err != nil {
		return domain.Run{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.Run{}, fmt.Errorf("commit run transition: %w", err)
	}
	return updated, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanRun(row rowScanner) (domain.Run, error) {
	var run domain.Run
	var input string
	var failure sql.NullString
	err := row.Scan(&run.ID, &run.TenantID, &run.AgentID, &run.ReleaseID, &run.SessionID, &run.Status, &input, &run.Version, &failure, &run.CreatedAt, &run.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Run{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Run{}, fmt.Errorf("scan run: %w", err)
	}
	run.Input = json.RawMessage(input)
	if failure.Valid {
		run.Failure = failure.String
	}
	return run, nil
}

func insertOutbox(ctx context.Context, tx *sql.Tx, eventType string, run domain.Run, now time.Time) error {
	payload, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("encode outbox event: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO outbox_events (id, aggregate_type, aggregate_id, aggregate_version, event_type, payload, created_at) VALUES ($1,'Run',$2,$3,$4,$5::jsonb,$6)`, run.ID+":"+fmt.Sprint(run.Version), run.ID, run.Version, eventType, string(payload), now)
	if err != nil {
		return fmt.Errorf("append outbox event: %w", err)
	}
	return nil
}
