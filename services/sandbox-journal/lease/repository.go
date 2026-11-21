// Package lease owns pre-Permit sandbox lease *intents*, not provider leases.
// This candidate never creates, dispatches or releases a real sandbox.
package lease

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalid = errors.New("invalid sandbox lease intent")
var ErrUnavailable = errors.New("sandbox lease-intent store unavailable")
var ErrNotFound = errors.New("sandbox lease intent not found")
var ErrConflict = errors.New("sandbox lease immutable identity conflict")
var ErrStaleGeneration = errors.New("sandbox lease-intent generation is stale")
var ErrCorrupt = errors.New("sandbox lease-intent record is corrupt")

const WaitingForPermit = "WAITING_FOR_PERMIT"
const CancelledBeforeProvision = "CANCELLED_BEFORE_PROVISION"

var opaqueRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var contentDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Intent struct {
	TenantID         string
	LeaseIntentID    string
	RunID            string
	RuntimeAttemptID string
	RequestDigest    string
}

func (in Intent) Validate() error {
	for _, ref := range []string{in.TenantID, in.LeaseIntentID, in.RunID, in.RuntimeAttemptID} {
		if !opaqueRef.MatchString(ref) {
			return ErrInvalid
		}
	}
	if !contentDigest.MatchString(in.RequestDigest) {
		return ErrInvalid
	}
	return nil
}

type Record struct {
	Intent     Intent
	Generation uint64
	State      string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type Repository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

const leaseColumns = "tenant_id,lease_intent_id,run_id,runtime_attempt_id,request_digest,generation,state,created_at,updated_at"

// Create commits a logical pre-Permit lease INTENT and the matching Outbox
// fact atomically. No SandboxProvider or Guard call is issued. Replays preserve
// a previously cancelled result; they NEVER re-enable a cancelled intent.
func (r *Repository) Create(ctx context.Context, in Intent) (Record, bool, error) {
	if err := in.Validate(); err != nil {
		return Record{}, false, err
	}
	if r == nil || r.pool == nil {
		return Record{}, false, ErrUnavailable
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Record{}, false, fmt.Errorf("begin sandbox lease intent: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	const insert = `INSERT INTO sandbox_lease_intents
	 (tenant_id,lease_intent_id,run_id,runtime_attempt_id,request_digest)
	 VALUES ($1,$2,$3,$4,$5)
	 ON CONFLICT (tenant_id,lease_intent_id) DO NOTHING
	 RETURNING ` + leaseColumns
	rec, err := scan(tx.QueryRow(ctx, insert,
		in.TenantID, in.LeaseIntentID, in.RunID, in.RuntimeAttemptID, in.RequestDigest))
	created := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		// The unique conflict waits for a pending creator to commit. Reading
		// the same immutable identity then returns its current, possibly
		// CANCELLED_BEFORE_PROVISION, status without reopening work.
		const existing = `SELECT ` + leaseColumns + ` FROM sandbox_lease_intents
		 WHERE tenant_id=$1 AND lease_intent_id=$2 FOR SHARE`
		rec, err = scan(tx.QueryRow(ctx, existing, in.TenantID, in.LeaseIntentID))
		if err != nil {
			return Record{}, false, fmt.Errorf("read lease intent replay: %w", err)
		}
		if rec.Intent != in {
			return Record{}, false, ErrConflict
		}
	} else if err != nil {
		return Record{}, false, fmt.Errorf("create sandbox lease intent: %w", err)
	}
	if created {
		const event = `INSERT INTO sandbox_lease_intent_events
		 (tenant_id,lease_intent_id,generation,event_type,payload)
		 VALUES ($1,$2,1,'sandbox.lease-intent.waiting-permit',
		 jsonb_build_object('run_id',$3::text,'runtime_attempt_id',$4::text,'request_digest',$5::text))`
		if _, err := tx.Exec(ctx, event,
			in.TenantID, in.LeaseIntentID, in.RunID, in.RuntimeAttemptID, in.RequestDigest); err != nil {
			return Record{}, false, fmt.Errorf("create lease intent outbox: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Record{}, false, fmt.Errorf("commit sandbox lease intent: %w", err)
	}
	return rec, created, nil
}

// CancelBeforeProvision increments Generation exactly once in a conditional
// PostgreSQL UPDATE. This cancels ONLY the unprovisioned INTENT, and must not
// be interpreted as a SandboxLease release, provider UID absence or permit
// revocation. Stale and duplicate CAS operations never append an event.
func (r *Repository) CancelBeforeProvision(
	ctx context.Context, tenant, leaseID string, expectedGeneration uint64,
) (Record, error) {
	if !opaqueRef.MatchString(tenant) || !opaqueRef.MatchString(leaseID) || expectedGeneration == 0 {
		return Record{}, ErrInvalid
	}
	if r == nil || r.pool == nil {
		return Record{}, ErrUnavailable
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("begin sandbox lease-intent CAS: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	const update = `UPDATE sandbox_lease_intents
	 SET state='CANCELLED_BEFORE_PROVISION', generation=generation+1, updated_at=clock_timestamp()
	 WHERE tenant_id=$1 AND lease_intent_id=$2 AND state='WAITING_FOR_PERMIT' AND generation=$3
	 RETURNING ` + leaseColumns
	rec, err := scan(tx.QueryRow(ctx, update, tenant, leaseID, expectedGeneration))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		const lookup = `SELECT EXISTS(SELECT 1 FROM sandbox_lease_intents
		 WHERE tenant_id=$1 AND lease_intent_id=$2)`
		if lookupErr := tx.QueryRow(ctx, lookup, tenant, leaseID).Scan(&exists); lookupErr != nil {
			return Record{}, fmt.Errorf("inspect denied lease-intent CAS: %w", lookupErr)
		}
		if !exists {
			return Record{}, ErrNotFound
		}
		return Record{}, ErrStaleGeneration
	}
	if err != nil {
		return Record{}, fmt.Errorf("CAS cancelled sandbox lease intent: %w", err)
	}
	const event = `INSERT INTO sandbox_lease_intent_events
	 (tenant_id,lease_intent_id,generation,event_type,payload)
	 VALUES ($1,$2,$3,'sandbox.lease-intent.cancelled-before-provision',
	 jsonb_build_object('run_id',$4::text,'runtime_attempt_id',$5::text,'request_digest',$6::text))`
	if _, err := tx.Exec(ctx, event, rec.Intent.TenantID, rec.Intent.LeaseIntentID,
		rec.Generation, rec.Intent.RunID, rec.Intent.RuntimeAttemptID, rec.Intent.RequestDigest); err != nil {
		return Record{}, fmt.Errorf("atomic cancelled lease-intent outbox: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Record{}, fmt.Errorf("commit cancelled lease intent: %w", err)
	}
	return rec, nil
}

// Get reads one tenant-scoped pre-Permit intent; no authorization is derived
// from its identifiers or status. The caller still needs trusted authn.
func (r *Repository) Get(ctx context.Context, tenant, leaseID string) (Record, error) {
	if !opaqueRef.MatchString(tenant) || !opaqueRef.MatchString(leaseID) {
		return Record{}, ErrInvalid
	}
	if r == nil || r.pool == nil {
		return Record{}, ErrUnavailable
	}
	const query = `SELECT ` + leaseColumns + ` FROM sandbox_lease_intents
	 WHERE tenant_id=$1 AND lease_intent_id=$2`
	rec, err := scan(r.pool.QueryRow(ctx, query, tenant, leaseID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("get sandbox lease intent: %w", err)
	}
	return rec, nil
}

func scan(row pgx.Row) (Record, error) {
	var rec Record
	var generation int64
	err := row.Scan(
		&rec.Intent.TenantID, &rec.Intent.LeaseIntentID, &rec.Intent.RunID,
		&rec.Intent.RuntimeAttemptID, &rec.Intent.RequestDigest,
		&generation, &rec.State, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return Record{}, err
	}
	if rec.Intent.Validate() != nil || rec.CreatedAt.IsZero() || rec.UpdatedAt.IsZero() ||
		rec.UpdatedAt.Before(rec.CreatedAt) ||
		!((rec.State == WaitingForPermit && generation == 1) ||
			(rec.State == CancelledBeforeProvision && generation == 2)) {
		return Record{}, ErrCorrupt
	}
	rec.Generation = uint64(generation)
	return rec, nil
}
