package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/domain"
)

func (s *Store) ClaimOutbox(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]domain.OutboxEvent, error) {
	if lease <= 0 || limit <= 0 {
		return nil, fmt.Errorf("lease duration and batch limit must be positive")
	}
	token, err := domain.NewID()
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin outbox claim: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		WITH candidates AS (
			SELECT id
			FROM outbox_events
			WHERE published_at IS NULL
			  AND next_attempt_at <= $1
			  AND (lease_until IS NULL OR lease_until <= $1)
			ORDER BY created_at, id
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		UPDATE outbox_events AS event
		SET lease_token = $3,
		    lease_until = $4,
		    attempts = event.attempts + 1
		FROM candidates
		WHERE event.id = candidates.id
		RETURNING event.id, event.aggregate_type, event.aggregate_id,
		          event.aggregate_version, event.event_type, event.payload::text,
		          event.attempts, event.created_at`, now.UTC(), limit, token, now.UTC().Add(lease))
	if err != nil {
		return nil, fmt.Errorf("claim outbox rows: %w", err)
	}
	defer rows.Close()

	events := make([]domain.OutboxEvent, 0, limit)
	for rows.Next() {
		var event domain.OutboxEvent
		var payload string
		if err := rows.Scan(&event.ID, &event.AggregateType, &event.AggregateID, &event.AggregateVersion, &event.EventType, &payload, &event.Attempts, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan claimed outbox event: %w", err)
		}
		event.Payload = []byte(payload)
		event.LeaseToken = token
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed outbox events: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit outbox claim: %w", err)
	}
	return events, nil
}

func (s *Store) AckOutbox(ctx context.Context, eventID, leaseToken string, at time.Time) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE outbox_events
		SET published_at=$1, lease_token=NULL, lease_until=NULL, last_error=NULL
		WHERE id=$2 AND lease_token=$3 AND lease_until > $1 AND published_at IS NULL`, at.UTC(), eventID, leaseToken)
	if err != nil {
		return fmt.Errorf("ack outbox event: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect outbox ack: %w", err)
	}
	if count != 1 {
		return domain.ErrOutboxLeaseLost
	}
	return nil
}

func (s *Store) NackOutbox(ctx context.Context, eventID, leaseToken, message string, retryAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE outbox_events
		SET next_attempt_at=$1, last_error=$2, lease_token=NULL, lease_until=NULL
		WHERE id=$3 AND lease_token=$4 AND lease_until > now() AND published_at IS NULL`, retryAt.UTC(), message, eventID, leaseToken)
	if err != nil {
		return fmt.Errorf("nack outbox event: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect outbox nack: %w", err)
	}
	if count != 1 {
		return domain.ErrOutboxLeaseLost
	}
	return nil
}
