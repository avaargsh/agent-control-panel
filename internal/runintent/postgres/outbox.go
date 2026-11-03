package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const maxOutboxBatchSize = 1000

var (
	ErrOutboxLeaseLost    = errors.New("outbox publish lease was lost")
	ErrInvalidOutboxLease = errors.New("invalid outbox publish lease")
	ErrInvalidOutboxCode  = errors.New("invalid outbox error code")
)

// OutboxLease identifies one claim attempt. Attempt is a fencing value: even
// when a worker process reuses its owner name, an older claim cannot ACK or
// retry an event after a later claim has incremented the attempt counter.
type OutboxLease struct {
	Event   Event
	Owner   string
	Attempt int
}

// ClaimOutbox atomically claims a bounded batch. It reclaims expired leases,
// and quarantines expired leases that exhausted their attempt budget. The
// returned lease must be acknowledged or retried with its exact owner and
// attempt. Publication must happen after this method commits.
func (r *Repository) ClaimOutbox(
	ctx context.Context,
	owner string,
	now time.Time,
	leaseTTL time.Duration,
	limit int,
	maxAttempts int,
) ([]OutboxLease, error) {
	if r == nil || r.pool == nil {
		return nil, errors.New("postgres run intent repository is not configured")
	}
	if strings.TrimSpace(owner) == "" || owner != strings.TrimSpace(owner) || len(owner) > 128 ||
		now.IsZero() || leaseTTL < time.Microsecond || limit < 1 || limit > maxOutboxBatchSize ||
		maxAttempts < 1 || maxAttempts > math.MaxInt32 {
		return nil, ErrInvalidOutboxLease
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin Outbox claim: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	// A worker may have died after claiming its final allowed attempt. Such a
	// row cannot be safely retried automatically: the broker may have accepted
	// the event before the worker died. Quarantine it for explicit inspection.
	if _, err := tx.Exec(ctx, `
		UPDATE outbox_events
		SET delivery_state = 'QUARANTINED',
		    lease_owner = NULL,
		    lease_expires_at = NULL,
		    last_error_code = 'OUTBOX_ATTEMPTS_EXHAUSTED'
		WHERE attempts >= $2
		  AND (
		    delivery_state = 'PENDING'
		    OR (delivery_state = 'PUBLISHING' AND lease_expires_at <= $1)
		  )
	`, now.UTC(), int32(maxAttempts)); err != nil {
		return nil, fmt.Errorf("quarantine exhausted Outbox leases: %w", err)
	}

	rows, err := tx.Query(ctx, `
		WITH candidates AS (
			SELECT candidate.event_id
			FROM outbox_events AS candidate
			WHERE candidate.attempts < $1
			  AND (
			    (candidate.delivery_state = 'PENDING' AND candidate.next_attempt_at <= $2)
			    OR
			    (candidate.delivery_state = 'PUBLISHING' AND candidate.lease_expires_at <= $2)
			  )
			  AND NOT EXISTS (
			    SELECT 1
			    FROM outbox_events AS predecessor
			    WHERE predecessor.producer = candidate.producer
			      AND predecessor.tenant_id = candidate.tenant_id
			      AND predecessor.aggregate_type = candidate.aggregate_type
			      AND predecessor.aggregate_id = candidate.aggregate_id
			      AND predecessor.aggregate_version < candidate.aggregate_version
			      AND predecessor.delivery_state <> 'PUBLISHED'
			  )
			ORDER BY
			  CASE WHEN candidate.delivery_state = 'PUBLISHING' THEN candidate.lease_expires_at ELSE candidate.next_attempt_at END,
			  candidate.created_at,
			  candidate.event_id
			LIMIT $3
			FOR UPDATE OF candidate SKIP LOCKED
		)
		UPDATE outbox_events AS event
		SET delivery_state = 'PUBLISHING',
		    attempts = event.attempts + 1,
		    lease_owner = $4,
		    lease_expires_at = $2 + ($5::double precision * INTERVAL '1 microsecond')
		FROM candidates
		WHERE event.event_id = candidates.event_id
		RETURNING
		  event.event_id::text,
		  event.producer,
		  event.event_type,
		  event.schema_version,
		  event.tenant_id,
		  event.aggregate_type,
		  event.aggregate_id,
		  event.aggregate_version,
		  event.occurred_at,
		  event.correlation_id,
		  event.causation_id,
		  event.traceparent,
		  event.payload::text,
		  event.attempts
	`, int32(maxAttempts), now.UTC(), limit, owner, leaseTTL.Microseconds())
	if err != nil {
		return nil, fmt.Errorf("claim Outbox events: %w", err)
	}

	leases := make([]OutboxLease, 0, limit)
	for rows.Next() {
		var event Event
		var aggregateVersion int64
		var causationID, traceparent pgtype.Text
		var payload string
		var attempts int32
		if err := rows.Scan(
			&event.ID,
			&event.Producer,
			&event.Type,
			&event.SchemaVersion,
			&event.TenantID,
			&event.AggregateType,
			&event.AggregateID,
			&aggregateVersion,
			&event.OccurredAt,
			&event.CorrelationID,
			&causationID,
			&traceparent,
			&payload,
			&attempts,
		); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan claimed Outbox event: %w", err)
		}
		if aggregateVersion <= 0 || attempts <= 0 {
			rows.Close()
			return nil, fmt.Errorf("%w: invalid aggregate version or attempt count", ErrCorruptRecord)
		}
		event.AggregateVersion = uint64(aggregateVersion)
		event.Payload = json.RawMessage(payload)
		if causationID.Valid {
			event.CausationID = causationID.String
		}
		if traceparent.Valid {
			event.Traceparent = traceparent.String
		}
		if err := validateOutboxEnvelope(event); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: %v", ErrCorruptRecord, err)
		}
		leases = append(leases, OutboxLease{
			Event:   event,
			Owner:   owner,
			Attempt: int(attempts),
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate claimed Outbox events: %w", err)
	}
	rows.Close()

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit Outbox claim: %w", err)
	}
	return leases, nil
}

// AcknowledgeOutbox marks a claimed event published only after the publisher
// has acknowledged it. The attempt predicate fences stale workers and makes
// the operation safe against an expired lease being reclaimed concurrently.
func (r *Repository) AcknowledgeOutbox(ctx context.Context, lease OutboxLease, publishedAt time.Time) error {
	if r == nil || r.pool == nil {
		return errors.New("postgres run intent repository is not configured")
	}
	if err := validateOutboxLease(lease); err != nil || publishedAt.IsZero() {
		return ErrInvalidOutboxLease
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE outbox_events
		SET delivery_state = 'PUBLISHED',
		    published_at = $4,
		    last_error_code = NULL,
		    lease_owner = NULL,
		    lease_expires_at = NULL
		WHERE event_id = $1::uuid
		  AND delivery_state = 'PUBLISHING'
		  AND lease_owner = $2
		  AND attempts = $3
		  AND lease_expires_at > clock_timestamp()
	`, lease.Event.ID, lease.Owner, int32(lease.Attempt), publishedAt.UTC())
	if err != nil {
		return fmt.Errorf("acknowledge Outbox event: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrOutboxLeaseLost
	}
	return nil
}

// RetryOutbox releases a failed claim and schedules exponential retry, or
// quarantines the event once maxAttempts has been reached. Only a bounded
// error code is persisted; publisher error strings may contain secret data.
func (r *Repository) RetryOutbox(
	ctx context.Context,
	lease OutboxLease,
	nextAttemptAt time.Time,
	errorCode string,
	maxAttempts int,
) (bool, error) {
	if r == nil || r.pool == nil {
		return false, errors.New("postgres run intent repository is not configured")
	}
	if err := validateOutboxLease(lease); err != nil || nextAttemptAt.IsZero() ||
		maxAttempts < 1 || maxAttempts > math.MaxInt32 {
		return false, ErrInvalidOutboxLease
	}
	if !validOutboxErrorCode(errorCode) {
		return false, ErrInvalidOutboxCode
	}

	var quarantined bool
	err := r.pool.QueryRow(ctx, `
		UPDATE outbox_events
		SET delivery_state = CASE WHEN attempts >= $5 THEN 'QUARANTINED' ELSE 'PENDING' END,
		    next_attempt_at = $4,
		    lease_owner = NULL,
		    lease_expires_at = NULL,
		    last_error_code = $6
		WHERE event_id = $1::uuid
		  AND delivery_state = 'PUBLISHING'
		  AND lease_owner = $2
		  AND attempts = $3
		  AND lease_expires_at > clock_timestamp()
		RETURNING delivery_state = 'QUARANTINED'
	`, lease.Event.ID, lease.Owner, int32(lease.Attempt), nextAttemptAt.UTC(), int32(maxAttempts), errorCode).Scan(&quarantined)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrOutboxLeaseLost
	}
	if err != nil {
		return false, fmt.Errorf("retry Outbox event: %w", err)
	}
	return quarantined, nil
}

func validateOutboxLease(lease OutboxLease) error {
	if strings.TrimSpace(lease.Owner) == "" || lease.Owner != strings.TrimSpace(lease.Owner) ||
		len(lease.Owner) > 128 || lease.Attempt < 1 || lease.Attempt > math.MaxInt32 ||
		strings.TrimSpace(lease.Event.ID) == "" {
		return ErrInvalidOutboxLease
	}
	return nil
}

func validateOutboxEnvelope(event Event) error {
	if strings.TrimSpace(event.ID) == "" || strings.TrimSpace(event.Producer) == "" ||
		strings.TrimSpace(event.Type) == "" || event.SchemaVersion <= 0 ||
		strings.TrimSpace(event.TenantID) == "" || strings.TrimSpace(event.AggregateType) == "" ||
		strings.TrimSpace(event.AggregateID) == "" || event.AggregateVersion == 0 ||
		event.OccurredAt.IsZero() || strings.TrimSpace(event.CorrelationID) == "" ||
		len(event.Payload) == 0 {
		return ErrInvalidEvent
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(event.Payload, &object); err != nil || object == nil {
		return ErrInvalidEvent
	}
	return nil
}

func validOutboxErrorCode(code string) bool {
	if len(code) == 0 || len(code) > 128 {
		return false
	}
	for _, char := range code {
		if !(char >= 'A' && char <= 'Z') &&
			!(char >= '0' && char <= '9') &&
			char != '_' && char != '-' {
			return false
		}
	}
	return true
}

// EventPublisher is the adapter boundary for a broker or another durable
// transport. Implementations must preserve event identity and report success
// only after the transport acknowledges the event.
type EventPublisher interface {
	Publish(context.Context, Event) error
}

// OutboxDispatcherOptions defines one worker's bounded delivery policy.
type OutboxDispatcherOptions struct {
	Owner          string
	BatchSize      int
	LeaseTTL       time.Duration
	PublishTimeout time.Duration
	MaxAttempts    int
	BaseBackoff    time.Duration
	MaxBackoff     time.Duration
	PollInterval   time.Duration
}

type OutboxDispatchResult struct {
	Claimed     int
	Published   int
	Retried     int
	Quarantined int
}

// OutboxDispatcher publishes claimed events outside database transactions.
// A database/lease error stops the current pass; a transport error is recorded
// as a retry or quarantine outcome and does not block the rest of the batch.
type OutboxDispatcher struct {
	repository *Repository
	publisher  EventPublisher
	options    OutboxDispatcherOptions
}

func NewOutboxDispatcher(repository *Repository, publisher EventPublisher, options OutboxDispatcherOptions) (*OutboxDispatcher, error) {
	if repository == nil || repository.pool == nil || publisher == nil ||
		strings.TrimSpace(options.Owner) == "" || options.Owner != strings.TrimSpace(options.Owner) ||
		len(options.Owner) > 128 || options.BatchSize < 1 || options.BatchSize > maxOutboxBatchSize ||
		options.LeaseTTL < time.Microsecond || options.PublishTimeout <= 0 ||
		options.PublishTimeout >= options.LeaseTTL/time.Duration(options.BatchSize+1) || options.MaxAttempts < 1 ||
		options.MaxAttempts > math.MaxInt32 || options.BaseBackoff <= 0 ||
		options.MaxBackoff < options.BaseBackoff || options.PollInterval <= 0 {
		return nil, errors.New("invalid Outbox dispatcher configuration")
	}
	return &OutboxDispatcher{repository: repository, publisher: publisher, options: options}, nil
}

// DispatchOnce claims and processes one bounded batch. Broker delivery and DB
// acknowledgement are separate operations, so a crash between them may cause
// a duplicate delivery. Consumers must deduplicate by event_id.
func (d *OutboxDispatcher) DispatchOnce(ctx context.Context) (OutboxDispatchResult, error) {
	if d == nil || d.repository == nil || d.publisher == nil {
		return OutboxDispatchResult{}, errors.New("Outbox dispatcher is not configured")
	}
	leases, err := d.repository.ClaimOutbox(
		ctx, d.options.Owner, time.Now().UTC(), d.options.LeaseTTL,
		d.options.BatchSize, d.options.MaxAttempts,
	)
	if err != nil {
		return OutboxDispatchResult{}, err
	}

	result := OutboxDispatchResult{Claimed: len(leases)}
	for _, lease := range leases {
		publishCtx, cancel := context.WithTimeout(ctx, d.options.PublishTimeout)
		publishErr := d.publisher.Publish(publishCtx, lease.Event)
		cancel()

		if publishErr != nil {
			errorCode := "PUBLISH_FAILED"
			if errors.Is(publishErr, context.DeadlineExceeded) {
				errorCode = "PUBLISH_TIMEOUT"
			} else if errors.Is(publishErr, context.Canceled) {
				errorCode = "PUBLISH_CANCELLED"
			}
			nextAttemptAt := time.Now().UTC().Add(retryDelay(lease.Attempt, d.options.BaseBackoff, d.options.MaxBackoff))
			quarantined, retryErr := d.repository.RetryOutbox(ctx, lease, nextAttemptAt, errorCode, d.options.MaxAttempts)
			if retryErr != nil {
				return result, fmt.Errorf("record Outbox publish failure: %w", retryErr)
			}
			if quarantined {
				result.Quarantined++
			} else {
				result.Retried++
			}
			continue
		}

		if err := d.repository.AcknowledgeOutbox(ctx, lease, time.Now().UTC()); err != nil {
			return result, fmt.Errorf("acknowledge published Outbox event: %w", err)
		}
		result.Published++
	}
	return result, nil
}

// Run polls continuously until cancellation. A persistent storage or lease
// error is returned so the process supervisor can restart or alert the worker.
func (d *OutboxDispatcher) Run(ctx context.Context) error {
	if d == nil || d.repository == nil || d.publisher == nil || d.options.PollInterval <= 0 {
		return errors.New("Outbox dispatcher is not configured")
	}
	ticker := time.NewTicker(d.options.PollInterval)
	defer ticker.Stop()

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if _, err := d.DispatchOnce(ctx); err != nil {
			if errors.Is(err, context.Canceled) && ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func retryDelay(attempt int, base, maximum time.Duration) time.Duration {
	if attempt <= 1 {
		if base > maximum {
			return maximum
		}
		return base
	}
	delay := base
	for i := 1; i < attempt && delay < maximum; i++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}
