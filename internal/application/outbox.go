package application

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/domain"
)

// OutboxRepository owns lease coordination and durable acknowledgement.
// ClaimOutbox must use an atomic database operation (for PostgreSQL,
// FOR UPDATE SKIP LOCKED) so multiple publishers cannot own the same lease.
type OutboxRepository interface {
	ClaimOutbox(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]domain.OutboxEvent, error)
	AckOutbox(ctx context.Context, eventID, leaseToken string, at time.Time) error
	NackOutbox(ctx context.Context, eventID, leaseToken, message string, retryAt time.Time) error
}

// OutboxHandler should be idempotent using event.ID. A process may crash after
// handling an event but before AckOutbox commits, causing a later redelivery.
type OutboxHandler interface {
	Handle(ctx context.Context, event domain.OutboxEvent) error
}

type PublishStats struct {
	Claimed   int `json:"claimed"`
	Published int `json:"published"`
	Retried   int `json:"retried"`
}

type OutboxPublisher struct {
	repo      OutboxRepository
	handler   OutboxHandler
	now       func() time.Time
	lease     time.Duration
	batchSize int
	baseDelay time.Duration
	maxDelay  time.Duration
}

func NewOutboxPublisher(repo OutboxRepository, handler OutboxHandler) *OutboxPublisher {
	return &OutboxPublisher{
		repo: repo, handler: handler, now: time.Now,
		lease: 30 * time.Second, batchSize: 32,
		baseDelay: time.Second, maxDelay: 5 * time.Minute,
	}
}

// Run polls until the context is cancelled. A repository/lease error stops the
// loop so the process supervisor can restart it; handler errors are persisted
// as retries by RunOnce and do not stop unrelated event delivery.
func (p *OutboxPublisher) Run(ctx context.Context, pollInterval time.Duration) error {
	if pollInterval <= 0 {
		return fmt.Errorf("poll interval must be positive")
	}
	for {
		if _, err := p.RunOnce(ctx); err != nil {
			return err
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (p *OutboxPublisher) RunOnce(ctx context.Context) (PublishStats, error) {
	if p.repo == nil || p.handler == nil {
		return PublishStats{}, fmt.Errorf("outbox repository and handler are required")
	}
	if p.lease <= 0 || p.batchSize <= 0 || p.baseDelay <= 0 || p.maxDelay < p.baseDelay {
		return PublishStats{}, fmt.Errorf("invalid outbox publisher configuration")
	}
	now := p.now().UTC()
	events, err := p.repo.ClaimOutbox(ctx, now, p.lease, p.batchSize)
	if err != nil {
		return PublishStats{}, fmt.Errorf("claim outbox events: %w", err)
	}
	stats := PublishStats{Claimed: len(events)}
	for _, event := range events {
		if err := event.Validate(); err != nil {
			if nackErr := p.repo.NackOutbox(ctx, event.ID, event.LeaseToken, safeError(err), now.Add(p.retryDelay(event.Attempts))); nackErr != nil {
				return stats, fmt.Errorf("invalid event %s (%v), nack failed: %w", event.ID, err, nackErr)
			}
			stats.Retried++
			continue
		}
		if err := p.handler.Handle(ctx, event); err != nil {
			retryAt := now.Add(p.retryDelay(event.Attempts))
			if nackErr := p.repo.NackOutbox(ctx, event.ID, event.LeaseToken, safeError(err), retryAt); nackErr != nil {
				return stats, fmt.Errorf("handle event %s failed (%v), nack failed: %w", event.ID, err, nackErr)
			}
			stats.Retried++
			continue
		}
		if err := p.repo.AckOutbox(ctx, event.ID, event.LeaseToken, p.now().UTC()); err != nil {
			return stats, fmt.Errorf("ack event %s: %w", event.ID, err)
		}
		stats.Published++
	}
	return stats, nil
}

func (p *OutboxPublisher) retryDelay(attempt int) time.Duration {
	delay := p.baseDelay
	if attempt < 1 {
		attempt = 1
	}
	for i := 1; i < attempt && delay < p.maxDelay; i++ {
		if delay > p.maxDelay/2 {
			return p.maxDelay
		}
		delay *= 2
	}
	if delay > p.maxDelay {
		return p.maxDelay
	}
	return delay
}

func safeError(err error) string {
	message := strings.TrimSpace(err.Error())
	if len(message) > 1024 {
		runes := []rune(message)
		message = string(runes[:min(len(runes), 1024)])
	}
	return message
}
