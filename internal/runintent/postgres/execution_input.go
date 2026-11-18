package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	"github.com/jackc/pgx/v5"
)

var ErrExecutionInputUnavailable = errors.New("run intent has no persisted execution input")

// CreateWithInput commits the exact bytes and existing immutable principal
// snapshot and Outbox event together. The legacy Create path cannot attach
// bytes later or replay an input-bearing intent.
func (r *Repository) CreateWithInput(ctx context.Context, intent runintent.Intent, event Event, raw []byte) (runintent.Intent, bool, error) {
	if len(raw) > runintent.MaxExecutionInputBytes {
		return runintent.Intent{}, false, runintent.ErrInvalidExecutionInput
	}
	input := bytes.Clone(raw)
	if err := runintent.VerifyExecutionInput(intent, input); err != nil {
		return runintent.Intent{}, false, err
	}
	return r.create(ctx, intent, event, nil, input)
}

func compareExecutionInputReplay(ctx context.Context, tx pgx.Tx, intent runintent.Intent, proposed []byte) error {
	var persisted []byte
	if err := tx.QueryRow(ctx, "SELECT execution_input FROM run_intents WHERE tenant_id=$1 AND id=$2::uuid",
		intent.TenantID, intent.ID).Scan(&persisted); err != nil {
		return fmt.Errorf("read execution input replay binding: %w", err)
	}
	if (persisted == nil) != (proposed == nil) || !bytes.Equal(persisted, proposed) {
		return ErrIdempotencyConflict
	}
	if persisted != nil && runintent.VerifyExecutionInput(intent, persisted) != nil {
		return ErrCorruptRecord
	}
	return nil
}

// GetExecutionInput is for trusted internal callers, not a public read API.
// The scope and bytes are read in a single statement; legacy NULLs fail
// closed. Do not log, reserialize, or place task input in Outbox payloads.
func (r *Repository) GetExecutionInput(ctx context.Context, tenantID, id string) ([]byte, error) {
	if r == nil || r.pool == nil || tenantID == "" || id == "" {
		return nil, runintent.ErrInvalidExecutionInput
	}
	var intent runintent.Intent
	var raw []byte
	err := r.pool.QueryRow(ctx, `SELECT tenant_id, project_id, agent_id, release_id,
		session_id, idempotency_key, request_digest, execution_input
		FROM run_intents WHERE tenant_id=$1 AND id=$2::uuid`, tenantID, id).Scan(
		&intent.TenantID, &intent.ProjectID, &intent.AgentID, &intent.ReleaseID,
		&intent.SessionID, &intent.IdempotencyKey, &intent.RequestDigest, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read persisted execution input: %w", err)
	}
	if raw == nil {
		return nil, ErrExecutionInputUnavailable
	}
	if err := runintent.VerifyExecutionInput(intent, raw); err != nil {
		return nil, ErrCorruptRecord
	}
	return raw, nil
}
