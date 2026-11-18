package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const maxInboxBatchSize = 1000

var (
	ErrInvalidInboxEvent = errors.New("invalid Inbox event")
	ErrInboxCursorMoved  = errors.New("Inbox aggregate cursor changed")
)

// InboxEvent contains the immutable event fields persisted by the Inbox.
type InboxEvent struct {
	ID               string
	Producer         string
	Type             string
	SchemaVersion    int32
	TenantID         string
	AggregateType    string
	AggregateID      string
	AggregateVersion uint64
	Payload          json.RawMessage
}

type InboxReceiveResult struct {
	Inserted    bool
	Duplicate   bool
	Quarantined bool
	Conflict    bool
}

type InboxApplyResult struct {
	Found       bool
	Applied     bool
	Quarantined bool
	Event       InboxEvent
	ReasonCode  string
}

type InboxBatchResult struct {
	Processed    int
	Applied      int
	Quarantined  int
	DeferredGaps int
}

// InboxEventApplier applies a projection in the same transaction as Inbox
// state and cursor updates. Apply must not perform external side effects.
type InboxEventApplier interface {
	Supports(InboxEvent) bool
	Apply(context.Context, pgx.Tx, InboxEvent) error
}

// persistInboxConflict retains the alternative envelope for forensic replay
// before the caller can acknowledge the conflicting broker delivery. It does
// not mutate the original event, including when that event was already APPLIED.
func persistInboxConflict(ctx context.Context, tx pgx.Tx, consumerName string, event Event) error {
	envelope := struct {
		Producer         string          `json:"producer"`
		Type             string          `json:"event_type"`
		SchemaVersion    int32           `json:"schema_version"`
		TenantID         string          `json:"tenant_id"`
		AggregateType    string          `json:"aggregate_type"`
		AggregateID      string          `json:"aggregate_id"`
		AggregateVersion uint64          `json:"aggregate_version"`
		Payload          json.RawMessage `json:"payload"`
	}{
		Producer: event.Producer, Type: event.Type, SchemaVersion: event.SchemaVersion,
		TenantID: event.TenantID, AggregateType: event.AggregateType,
		AggregateID: event.AggregateID, AggregateVersion: event.AggregateVersion,
		Payload: event.Payload,
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode Inbox conflict evidence: %w", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	if _, err := tx.Exec(ctx, `
		INSERT INTO inbox_event_conflicts (
			consumer_name,event_id,conflict_sha256,producer,event_type,schema_version,
			tenant_id,aggregate_type,aggregate_id,aggregate_version,payload
		) VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
		ON CONFLICT (consumer_name,event_id,conflict_sha256) DO NOTHING
	`, consumerName, event.ID, digest, event.Producer, event.Type, event.SchemaVersion,
		event.TenantID, event.AggregateType, event.AggregateID,
		int64(event.AggregateVersion), []byte(event.Payload)); err != nil {
		return fmt.Errorf("persist Inbox conflicting delivery: %w", err)
	}
	return nil
}

// ReceiveInboxEvent persists a broker delivery before its transport is ACKed.
// Redelivery is idempotent by (consumer_name,event_id). Aggregate-version
// collisions are retained and quarantined instead of overwriting prior events.
func (r *Repository) ReceiveInboxEvent(ctx context.Context, consumerName string, event Event) (InboxReceiveResult, error) {
	if r == nil || r.pool == nil {
		return InboxReceiveResult{}, errors.New("postgres run intent repository is not configured")
	}
	if strings.TrimSpace(consumerName) == "" || consumerName != strings.TrimSpace(consumerName) ||
		len(consumerName) > 128 || validateOutboxEnvelope(event) != nil ||
		event.AggregateVersion > math.MaxInt64 {
		return InboxReceiveResult{}, ErrInvalidInboxEvent
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return InboxReceiveResult{}, fmt.Errorf("begin Inbox receive: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var insertedID string
	err = tx.QueryRow(ctx, `
		INSERT INTO inbox_events (
			consumer_name,event_id,producer,event_type,schema_version,tenant_id,
			aggregate_type,aggregate_id,aggregate_version,payload,state
		) VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,'RECEIVED')
		ON CONFLICT (consumer_name,event_id) DO NOTHING
		RETURNING event_id::text
	`, consumerName, event.ID, event.Producer, event.Type, event.SchemaVersion,
		event.TenantID, event.AggregateType, event.AggregateID,
		int64(event.AggregateVersion), []byte(event.Payload)).Scan(&insertedID)

	if errors.Is(err, pgx.ErrNoRows) {
		var state string
		var matches bool
		err = tx.QueryRow(ctx, `
			SELECT state,
				producer = $3
				AND event_type = $4
				AND schema_version = $5
				AND tenant_id = $6
				AND aggregate_type = $7
				AND aggregate_id = $8
				AND aggregate_version = $9
				AND payload = $10::jsonb
			FROM inbox_events
			WHERE consumer_name = $1 AND event_id = $2::uuid
			FOR UPDATE
		`, consumerName, event.ID, event.Producer, event.Type, event.SchemaVersion,
			event.TenantID, event.AggregateType, event.AggregateID,
			int64(event.AggregateVersion), []byte(event.Payload)).Scan(&state, &matches)
		if err != nil {
			return InboxReceiveResult{}, fmt.Errorf("inspect Inbox duplicate: %w", err)
		}

		if !matches {
			// Preserve already-applied history. A conflicting redelivery that
			// has not yet been applied is quarantined and cannot advance a cursor.
			if state == "RECEIVED" {
				if _, err := tx.Exec(ctx, `
					UPDATE inbox_events
					SET state = 'QUARANTINED', error_code = 'EVENT_ID_CONFLICT'
					WHERE consumer_name = $1 AND event_id = $2::uuid AND state = 'RECEIVED'
				`, consumerName, event.ID); err != nil {
					return InboxReceiveResult{}, fmt.Errorf("quarantine conflicting Inbox event ID: %w", err)
				}
				state = "QUARANTINED"
			}
			if err := persistInboxConflict(ctx, tx, consumerName, event); err != nil {
				return InboxReceiveResult{}, err
			}
			if err := tx.Commit(ctx); err != nil {
				return InboxReceiveResult{}, fmt.Errorf("commit Inbox event conflict: %w", err)
			}
			return InboxReceiveResult{
				Duplicate: true, Quarantined: state == "QUARANTINED", Conflict: true,
			}, nil
		}

		if err := tx.Commit(ctx); err != nil {
			return InboxReceiveResult{}, fmt.Errorf("commit Inbox duplicate: %w", err)
		}
		return InboxReceiveResult{Duplicate: true, Quarantined: state == "QUARANTINED"}, nil
	}
	if err != nil {
		return InboxReceiveResult{}, fmt.Errorf("insert Inbox event: %w", err)
	}

	var claimedID string
	err = tx.QueryRow(ctx, `
		INSERT INTO inbox_aggregate_claims (
			consumer_name,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_id
		) VALUES ($1,$2,$3,$4,$5,$6::uuid)
		ON CONFLICT DO NOTHING
		RETURNING event_id::text
	`, consumerName, event.TenantID, event.AggregateType, event.AggregateID,
		int64(event.AggregateVersion), event.ID).Scan(&claimedID)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, updateErr := tx.Exec(ctx, `
			UPDATE inbox_events
			SET state = 'QUARANTINED', error_code = 'AGGREGATE_VERSION_CONFLICT'
			WHERE consumer_name = $1 AND event_id = $2::uuid AND state = 'RECEIVED'
		`, consumerName, event.ID); updateErr != nil {
			return InboxReceiveResult{}, fmt.Errorf("quarantine conflicting aggregate version: %w", updateErr)
		}
		if err := tx.Commit(ctx); err != nil {
			return InboxReceiveResult{}, fmt.Errorf("commit aggregate version quarantine: %w", err)
		}
		return InboxReceiveResult{Inserted: true, Quarantined: true}, nil
	}
	if err != nil {
		return InboxReceiveResult{}, fmt.Errorf("claim Inbox aggregate version: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO inbox_cursors (
			consumer_name,tenant_id,aggregate_type,aggregate_id,last_applied_version
		) VALUES ($1,$2,$3,$4,0)
		ON CONFLICT (consumer_name,tenant_id,aggregate_type,aggregate_id) DO NOTHING
	`, consumerName, event.TenantID, event.AggregateType, event.AggregateID); err != nil {
		return InboxReceiveResult{}, fmt.Errorf("initialize Inbox aggregate cursor: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return InboxReceiveResult{}, fmt.Errorf("commit Inbox event: %w", err)
	}
	return InboxReceiveResult{Inserted: true}, nil
}

// ApplyNextInboxEvent applies one contiguous event for one aggregate. Cursor
// and event rows are locked together; projection writes, APPLIED state and
// cursor advancement commit atomically.
func (r *Repository) ApplyNextInboxEvent(ctx context.Context, consumerName string, applier InboxEventApplier) (InboxApplyResult, error) {
	if r == nil || r.pool == nil {
		return InboxApplyResult{}, errors.New("postgres run intent repository is not configured")
	}
	if strings.TrimSpace(consumerName) == "" || consumerName != strings.TrimSpace(consumerName) ||
		len(consumerName) > 128 || applier == nil {
		return InboxApplyResult{}, errors.New("invalid Inbox applier configuration")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return InboxApplyResult{}, fmt.Errorf("begin Inbox apply: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var event InboxEvent
	var aggregateVersion, lastAppliedVersion int64
	var payload string
	err = tx.QueryRow(ctx, `
		SELECT e.event_id::text,e.producer,e.event_type,e.schema_version,e.tenant_id,
			e.aggregate_type,e.aggregate_id,e.aggregate_version,e.payload::text,
			c.last_applied_version
		FROM inbox_events e
		JOIN inbox_cursors c
			ON c.consumer_name = e.consumer_name
			AND c.tenant_id = e.tenant_id
			AND c.aggregate_type = e.aggregate_type
			AND c.aggregate_id = e.aggregate_id
		WHERE e.consumer_name = $1
			AND e.state = 'RECEIVED'
			AND e.aggregate_version = c.last_applied_version + 1
		ORDER BY e.received_at,e.event_id
		LIMIT 1
		FOR UPDATE OF c,e SKIP LOCKED
	`, consumerName).Scan(
		&event.ID, &event.Producer, &event.Type, &event.SchemaVersion, &event.TenantID,
		&event.AggregateType, &event.AggregateID, &aggregateVersion, &payload,
		&lastAppliedVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return InboxApplyResult{}, nil
	}
	if err != nil {
		return InboxApplyResult{}, fmt.Errorf("claim next Inbox event: %w", err)
	}
	if aggregateVersion <= 0 || lastAppliedVersion < 0 || aggregateVersion != lastAppliedVersion+1 {
		return InboxApplyResult{}, ErrCorruptRecord
	}
	event.AggregateVersion = uint64(aggregateVersion)
	event.Payload = json.RawMessage(payload)
	if err := validateStoredInboxEvent(event); err != nil {
		return InboxApplyResult{}, fmt.Errorf("%w: %v", ErrCorruptRecord, err)
	}

	result := InboxApplyResult{Found: true, Event: event}
	if !applier.Supports(event) {
		tag, updateErr := tx.Exec(ctx, `
			UPDATE inbox_events
			SET state = 'QUARANTINED', error_code = 'UNSUPPORTED_EVENT_SCHEMA'
			WHERE consumer_name = $1 AND event_id = $2::uuid AND state = 'RECEIVED'
		`, consumerName, event.ID)
		if updateErr != nil {
			return InboxApplyResult{}, fmt.Errorf("quarantine unsupported Inbox event: %w", updateErr)
		}
		if tag.RowsAffected() != 1 {
			return InboxApplyResult{}, ErrInboxCursorMoved
		}
		if err := tx.Commit(ctx); err != nil {
			return InboxApplyResult{}, fmt.Errorf("commit unsupported Inbox event quarantine: %w", err)
		}
		result.Quarantined = true
		result.ReasonCode = "UNSUPPORTED_EVENT_SCHEMA"
		return result, nil
	}

	if err := applier.Apply(ctx, tx, event); err != nil {
		return InboxApplyResult{}, fmt.Errorf("apply Inbox event %s: %w", event.ID, err)
	}

	tag, err := tx.Exec(ctx, `
		UPDATE inbox_events
		SET state = 'APPLIED', applied_at = clock_timestamp(), error_code = NULL
		WHERE consumer_name = $1 AND event_id = $2::uuid AND state = 'RECEIVED'
	`, consumerName, event.ID)
	if err != nil {
		return InboxApplyResult{}, fmt.Errorf("mark Inbox event applied: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return InboxApplyResult{}, ErrInboxCursorMoved
	}

	tag, err = tx.Exec(ctx, `
		UPDATE inbox_cursors
		SET last_applied_version = $5, updated_at = clock_timestamp()
		WHERE consumer_name = $1 AND tenant_id = $2 AND aggregate_type = $3
			AND aggregate_id = $4 AND last_applied_version = $6
	`, consumerName, event.TenantID, event.AggregateType, event.AggregateID,
		int64(event.AggregateVersion), lastAppliedVersion)
	if err != nil {
		return InboxApplyResult{}, fmt.Errorf("advance Inbox aggregate cursor: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return InboxApplyResult{}, ErrInboxCursorMoved
	}
	if err := tx.Commit(ctx); err != nil {
		return InboxApplyResult{}, fmt.Errorf("commit Inbox projection and cursor: %w", err)
	}

	result.Applied = true
	return result, nil
}

func validateStoredInboxEvent(event InboxEvent) error {
	if strings.TrimSpace(event.ID) == "" || strings.TrimSpace(event.Producer) == "" ||
		strings.TrimSpace(event.Type) == "" || event.SchemaVersion <= 0 ||
		strings.TrimSpace(event.TenantID) == "" || strings.TrimSpace(event.AggregateType) == "" ||
		strings.TrimSpace(event.AggregateID) == "" || event.AggregateVersion == 0 {
		return ErrInvalidInboxEvent
	}
	var object map[string]json.RawMessage
	if len(event.Payload) == 0 || json.Unmarshal(event.Payload, &object) != nil || object == nil {
		return ErrInvalidInboxEvent
	}
	return nil
}

// ApplyInboxBatch drains up to limit contiguous events. Version gaps remain
// RECEIVED and are counted; they never advance the aggregate cursor.
func (r *Repository) ApplyInboxBatch(ctx context.Context, consumerName string, applier InboxEventApplier, limit int) (InboxBatchResult, error) {
	if limit < 1 || limit > maxInboxBatchSize {
		return InboxBatchResult{}, errors.New("Inbox batch limit must be between 1 and 1000")
	}
	result := InboxBatchResult{}
	for result.Processed < limit {
		next, err := r.ApplyNextInboxEvent(ctx, consumerName, applier)
		if err != nil {
			return result, err
		}
		if !next.Found {
			break
		}
		result.Processed++
		if next.Applied {
			result.Applied++
		}
		if next.Quarantined {
			result.Quarantined++
		}
	}
	gaps, err := r.countInboxGaps(ctx, consumerName)
	if err != nil {
		return result, err
	}
	result.DeferredGaps = gaps
	return result, nil
}

func (r *Repository) countInboxGaps(ctx context.Context, consumerName string) (int, error) {
	if r == nil || r.pool == nil {
		return 0, errors.New("postgres run intent repository is not configured")
	}
	var gaps int
	err := r.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM (
			SELECT e.tenant_id,e.aggregate_type,e.aggregate_id,
				MIN(e.aggregate_version) AS first_pending_version,
				c.last_applied_version
			FROM inbox_events e
			JOIN inbox_cursors c
				ON c.consumer_name = e.consumer_name
				AND c.tenant_id = e.tenant_id
				AND c.aggregate_type = e.aggregate_type
				AND c.aggregate_id = e.aggregate_id
			WHERE e.consumer_name = $1 AND e.state = 'RECEIVED'
			GROUP BY e.tenant_id,e.aggregate_type,e.aggregate_id,c.last_applied_version
			HAVING MIN(e.aggregate_version) > c.last_applied_version + 1
		) gaps
	`, consumerName).Scan(&gaps)
	if err != nil {
		return 0, fmt.Errorf("count Inbox aggregate version gaps: %w", err)
	}
	return gaps, nil
}

type InboxWorkerOptions struct {
	ConsumerName string
	BatchSize    int
	PollInterval time.Duration
}

type InboxWorker struct {
	repository *Repository
	applier    InboxEventApplier
	options    InboxWorkerOptions
}

func NewInboxWorker(repository *Repository, applier InboxEventApplier, options InboxWorkerOptions) (*InboxWorker, error) {
	if repository == nil || repository.pool == nil || applier == nil ||
		strings.TrimSpace(options.ConsumerName) == "" ||
		options.ConsumerName != strings.TrimSpace(options.ConsumerName) ||
		len(options.ConsumerName) > 128 ||
		options.BatchSize < 1 || options.BatchSize > maxInboxBatchSize ||
		options.PollInterval <= 0 {
		return nil, errors.New("invalid Inbox worker configuration")
	}
	return &InboxWorker{repository: repository, applier: applier, options: options}, nil
}

func (w *InboxWorker) ProcessOnce(ctx context.Context) (InboxBatchResult, error) {
	if w == nil || w.repository == nil || w.applier == nil {
		return InboxBatchResult{}, errors.New("Inbox worker is not configured")
	}
	return w.repository.ApplyInboxBatch(ctx, w.options.ConsumerName, w.applier, w.options.BatchSize)
}

// Run drains full batches immediately and sleeps only when no more contiguous
// work is available. Storage or applier errors escape to the process supervisor.
func (w *InboxWorker) Run(ctx context.Context) error {
	if w == nil || w.repository == nil || w.applier == nil || w.options.PollInterval <= 0 {
		return errors.New("Inbox worker is not configured")
	}
	ticker := time.NewTicker(w.options.PollInterval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		result, err := w.ProcessOnce(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) && ctx.Err() != nil {
				return nil
			}
			return err
		}
		if result.Processed >= w.options.BatchSize {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
