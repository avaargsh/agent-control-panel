// Package postgres persists Control Plane-owned RunIntent state and its Outbox.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound             = errors.New("run intent not found")
	ErrStaleVersion         = errors.New("stale run intent version")
	ErrIdempotencyConflict  = errors.New("idempotency key reused with a different request digest")
	ErrImmutableFieldChange = errors.New("run intent immutable identity changed")
	ErrInvalidTransition    = errors.New("invalid persisted run intent transition")
	ErrFenceRegression      = errors.New("run intent fencing token regression")
	ErrInvalidEvent         = errors.New("invalid run intent outbox event")
	ErrCorruptRecord        = errors.New("corrupt persisted run intent")
)

const (
	operationCreate = "run_intent.create"
	eventCreated    = "agent.run-intent.created"
	aggregateType   = "run_intent"
)

const selectIntentColumns = "id::text, tenant_id, principal_id, project_id, agent_id, release_id, session_id, idempotency_key, request_digest, version, fence_token, status, lease_owner, lease_expires_at, runtime_run_id, workflow_id, rejection_code, manual_review_code"

// Event is an immutable Outbox envelope. Payload must be a JSON object.
type Event struct {
	ID               string
	Producer         string
	Type             string
	SchemaVersion    int32
	TenantID         string
	AggregateType    string
	AggregateID      string
	AggregateVersion uint64
	OccurredAt       time.Time
	CorrelationID    string
	CausationID      string
	Traceparent      string
	Payload          json.RawMessage
}

// Repository owns the transaction boundary between RunIntent and Outbox.
type Repository struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// Create atomically claims the idempotency key, inserts the RunIntent and
// appends its creation event. A matching replay returns the original record.
func (r *Repository) Create(ctx context.Context, intent runintent.Intent, event Event) (runintent.Intent, bool, error) {
	if r == nil || r.pool == nil {
		return runintent.Intent{}, false, errors.New("postgres run intent repository is not configured")
	}
	if err := intent.Validate(); err != nil {
		return runintent.Intent{}, false, err
	}
	if intent.Status != runintent.Pending || intent.Version != 1 || intent.FenceToken != 0 {
		return runintent.Intent{}, false, ErrInvalidTransition
	}
	if err := validateEvent(event, intent, eventCreated); err != nil {
		return runintent.Intent{}, false, err
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return runintent.Intent{}, false, fmt.Errorf("begin RunIntent create: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	query := "INSERT INTO run_intents (" +
		"id, tenant_id, principal_id, operation, project_id, agent_id, release_id, session_id, " +
		"idempotency_key, request_digest, status, version, fence_token, lease_owner, lease_expires_at, " +
		"runtime_run_id, workflow_id, rejection_code, manual_review_code) " +
		"VALUES ($1::uuid, $2, $3, '" + operationCreate + "', $4, $5, $6, $7, $8, $9, $10, $11, $12, " +
		"$13, $14, $15, $16, $17, $18) " +
		"ON CONFLICT (tenant_id, principal_id, operation, idempotency_key) DO NOTHING " +
		"RETURNING " + selectIntentColumns

	persisted, err := scanIntent(tx.QueryRow(ctx, query,
		intent.ID, intent.TenantID, intent.PrincipalID, intent.ProjectID, intent.AgentID,
		intent.ReleaseID, intent.SessionID, intent.IdempotencyKey, intent.RequestDigest,
		string(intent.Status), int64(intent.Version), int64(intent.FenceToken),
		nullableString(intent.LeaseOwner), nullableTime(intent.LeaseExpiresAt),
		nullableString(intent.RunID), nullableString(intent.WorkflowID),
		nullableString(intent.RejectionCode), nullableString(intent.ManualReviewCode),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		existing, lookupErr := scanIntent(tx.QueryRow(ctx,
			"SELECT "+selectIntentColumns+" FROM run_intents WHERE tenant_id = $1 AND principal_id = $2 AND operation = $3 AND idempotency_key = $4",
			intent.TenantID, intent.PrincipalID, operationCreate, intent.IdempotencyKey,
		))
		if lookupErr != nil {
			return runintent.Intent{}, false, fmt.Errorf("load idempotency replay: %w", lookupErr)
		}
		if existing.RequestDigest != intent.RequestDigest || !sameCreationIdentity(existing, intent) {
			return runintent.Intent{}, false, ErrIdempotencyConflict
		}
		return existing, false, nil
	}
	if err != nil {
		return runintent.Intent{}, false, fmt.Errorf("insert RunIntent: %w", err)
	}
	if err := insertEvent(ctx, tx, event); err != nil {
		return runintent.Intent{}, false, fmt.Errorf("insert RunIntent created event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return runintent.Intent{}, false, fmt.Errorf("commit RunIntent create: %w", err)
	}
	return persisted, true, nil
}

// Get returns a tenant-scoped RunIntent and validates the stored state before
// exposing it to callers.
func (r *Repository) Get(ctx context.Context, tenantID, id string) (runintent.Intent, error) {
	if r == nil || r.pool == nil {
		return runintent.Intent{}, errors.New("postgres run intent repository is not configured")
	}
	intent, err := scanIntent(r.pool.QueryRow(ctx,
		"SELECT "+selectIntentColumns+" FROM run_intents WHERE tenant_id = $1 AND id = $2::uuid",
		tenantID, id,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return runintent.Intent{}, ErrNotFound
	}
	if err != nil {
		return runintent.Intent{}, fmt.Errorf("read RunIntent: %w", err)
	}
	return intent, nil
}

// CompareAndSwap persists one validated state transition and its event in one
// transaction. The row lock and version predicate protect concurrent writers;
// the transition check prevents callers from skipping domain states.
func (r *Repository) CompareAndSwap(ctx context.Context, tenantID, id string, expectedVersion uint64, next runintent.Intent, event Event) (runintent.Intent, error) {
	if r == nil || r.pool == nil {
		return runintent.Intent{}, errors.New("postgres run intent repository is not configured")
	}
	if err := next.Validate(); err != nil {
		return runintent.Intent{}, err
	}
	if expectedVersion >= uint64(math.MaxInt64) || expectedVersion == 0 || next.Version != expectedVersion+1 ||
		next.Version > math.MaxInt64 || next.FenceToken > math.MaxInt64 {
		return runintent.Intent{}, ErrInvalidTransition
	}
	if next.ID != id || next.TenantID != tenantID {
		return runintent.Intent{}, ErrImmutableFieldChange
	}
	if err := validateEvent(event, next, ""); err != nil {
		return runintent.Intent{}, err
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return runintent.Intent{}, fmt.Errorf("begin RunIntent transition: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	current, err := scanIntent(tx.QueryRow(ctx,
		"SELECT "+selectIntentColumns+" FROM run_intents WHERE tenant_id = $1 AND id = $2::uuid FOR UPDATE",
		tenantID, id,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return runintent.Intent{}, ErrNotFound
	}
	if err != nil {
		return runintent.Intent{}, fmt.Errorf("lock RunIntent: %w", err)
	}
	if current.Version != expectedVersion {
		return runintent.Intent{}, ErrStaleVersion
	}
	if !sameImmutableIdentity(current, next) {
		return runintent.Intent{}, ErrImmutableFieldChange
	}
	if !allowedTransition(current.Status, next.Status) || next.Version != current.Version+1 {
		return runintent.Intent{}, ErrInvalidTransition
	}
	if next.FenceToken < current.FenceToken || current.FenceToken == math.MaxInt64 && next.FenceToken != current.FenceToken ||
		next.FenceToken-current.FenceToken > 1 {
		return runintent.Intent{}, ErrFenceRegression
	}
	acquiringLease := current.Status == runintent.Pending && next.Status == runintent.Dispatching ||
		current.Status == runintent.Unknown && next.Status == runintent.Reconciling
	if acquiringLease && next.FenceToken != current.FenceToken+1 {
		return runintent.Intent{}, ErrFenceRegression
	}
	if event.AggregateVersion != next.Version {
		return runintent.Intent{}, ErrInvalidEvent
	}

	updated, err := scanIntent(tx.QueryRow(ctx,
		"UPDATE run_intents SET status = $3, version = $4, fence_token = $5, lease_owner = $6, "+
			"lease_expires_at = $7, runtime_run_id = $8, workflow_id = $9, rejection_code = $10, "+
			"manual_review_code = $11, updated_at = now() "+
			"WHERE id = $1::uuid AND tenant_id = $2 AND version = $12 RETURNING "+selectIntentColumns,
		id, tenantID, string(next.Status), int64(next.Version), int64(next.FenceToken),
		nullableString(next.LeaseOwner), nullableTime(next.LeaseExpiresAt),
		nullableString(next.RunID), nullableString(next.WorkflowID),
		nullableString(next.RejectionCode), nullableString(next.ManualReviewCode), int64(expectedVersion),
	))
	if err != nil {
		return runintent.Intent{}, fmt.Errorf("update RunIntent: %w", err)
	}
	if err := insertEvent(ctx, tx, event); err != nil {
		return runintent.Intent{}, fmt.Errorf("insert RunIntent transition event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return runintent.Intent{}, fmt.Errorf("commit RunIntent transition: %w", err)
	}
	return updated, nil
}

func validateEvent(event Event, intent runintent.Intent, requiredType string) error {
	if event.ID == "" || event.Producer == "" || event.Type == "" || event.SchemaVersion <= 0 ||
		event.TenantID != intent.TenantID || event.AggregateType != aggregateType ||
		event.AggregateID != intent.ID || event.AggregateVersion != intent.Version ||
		event.OccurredAt.IsZero() || event.CorrelationID == "" {
		return ErrInvalidEvent
	}
	if requiredType != "" && event.Type != requiredType {
		return ErrInvalidEvent
	}
	if requiredType == "" && event.Type == eventCreated {
		return ErrInvalidEvent
	}
	var object map[string]json.RawMessage
	if len(event.Payload) == 0 || json.Unmarshal(event.Payload, &object) != nil || object == nil {
		return ErrInvalidEvent
	}
	if event.AggregateVersion > math.MaxInt64 {
		return ErrInvalidEvent
	}
	return nil
}

func insertEvent(ctx context.Context, tx pgx.Tx, event Event) error {
	_, err := tx.Exec(ctx,
		"INSERT INTO outbox_events ("+
			"event_id, producer, event_type, schema_version, tenant_id, aggregate_type, aggregate_id, "+
			"aggregate_version, occurred_at, correlation_id, causation_id, traceparent, payload"+
			") VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb)",
		event.ID, event.Producer, event.Type, event.SchemaVersion, event.TenantID,
		event.AggregateType, event.AggregateID, int64(event.AggregateVersion),
		event.OccurredAt, event.CorrelationID, nullableString(event.CausationID),
		nullableString(event.Traceparent), []byte(event.Payload),
	)
	return err
}

func scanIntent(row pgx.Row) (runintent.Intent, error) {
	var intent runintent.Intent
	var version, fenceToken int64
	var status string
	var leaseOwner, runID, workflowID, rejectionCode, manualReviewCode pgtype.Text
	var leaseExpiresAt pgtype.Timestamptz
	err := row.Scan(
		&intent.ID, &intent.TenantID, &intent.PrincipalID, &intent.ProjectID, &intent.AgentID,
		&intent.ReleaseID, &intent.SessionID, &intent.IdempotencyKey, &intent.RequestDigest,
		&version, &fenceToken, &status, &leaseOwner, &leaseExpiresAt, &runID,
		&workflowID, &rejectionCode, &manualReviewCode,
	)
	if err != nil {
		return runintent.Intent{}, err
	}
	if version <= 0 || fenceToken < 0 {
		return runintent.Intent{}, ErrCorruptRecord
	}
	intent.Version = uint64(version)
	intent.FenceToken = uint64(fenceToken)
	intent.Status = runintent.Status(status)
	if leaseOwner.Valid {
		intent.LeaseOwner = leaseOwner.String
	}
	if leaseExpiresAt.Valid {
		intent.LeaseExpiresAt = leaseExpiresAt.Time
	}
	if runID.Valid {
		intent.RunID = runID.String
	}
	if workflowID.Valid {
		intent.WorkflowID = workflowID.String
	}
	if rejectionCode.Valid {
		intent.RejectionCode = rejectionCode.String
	}
	if manualReviewCode.Valid {
		intent.ManualReviewCode = manualReviewCode.String
	}
	if err := intent.Validate(); err != nil {
		return runintent.Intent{}, fmt.Errorf("%w: %v", ErrCorruptRecord, err)
	}
	return intent, nil
}

func sameImmutableIdentity(a, b runintent.Intent) bool {
	return a.ID == b.ID && a.TenantID == b.TenantID && a.PrincipalID == b.PrincipalID &&
		a.ProjectID == b.ProjectID && a.AgentID == b.AgentID && a.ReleaseID == b.ReleaseID &&
		a.SessionID == b.SessionID && a.IdempotencyKey == b.IdempotencyKey &&
		a.RequestDigest == b.RequestDigest
}

func allowedTransition(from, to runintent.Status) bool {
	switch from {
	case runintent.Pending:
		return to == runintent.Dispatching
	case runintent.Dispatching:
		return to == runintent.Accepted || to == runintent.Rejected ||
			to == runintent.Unknown || to == runintent.ManualReview
	case runintent.Unknown:
		return to == runintent.Reconciling
	case runintent.Reconciling:
		return to == runintent.Accepted || to == runintent.Pending ||
			to == runintent.Unknown || to == runintent.Rejected ||
			to == runintent.ManualReview
	default:
		return false
	}
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func sameCreationIdentity(existing, requested runintent.Intent) bool {
	// The idempotency uniqueness domain already binds tenant/principal/key.
	// These ownership dimensions live beside the digest in dedicated columns,
	// so compare them explicitly before returning an existing resource. The
	// proposed ID is intentionally excluded: retries may generate a new
	// candidate ID, but must receive the original committed identity.
	return existing.TenantID == requested.TenantID &&
		existing.PrincipalID == requested.PrincipalID &&
		existing.ProjectID == requested.ProjectID &&
		existing.AgentID == requested.AgentID &&
		existing.ReleaseID == requested.ReleaseID &&
		existing.SessionID == requested.SessionID &&
		existing.IdempotencyKey == requested.IdempotencyKey &&
		existing.RequestDigest == requested.RequestDigest
}
