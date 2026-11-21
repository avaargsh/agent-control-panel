// Package lease owns pre-Permit sandbox lease *intents*, not provider leases.
// This candidate never creates, dispatches or releases a real sandbox.
package lease

import (
	"context"
	"errors"
	"time"

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

type Intent struct {
	TenantID         string
	LeaseIntentID    string
	RunID            string
	RuntimeAttemptID string
	RequestDigest    string
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

func (r *Repository) Create(ctx context.Context, in Intent) (Record, bool, error) {
	return Record{}, false, ErrUnavailable
}

func (r *Repository) CancelBeforeProvision(ctx context.Context, tenant, leaseID string, expectedGeneration uint64) (Record, error) {
	return Record{}, ErrUnavailable
}

func (r *Repository) Get(ctx context.Context, tenant, leaseID string) (Record, error) {
	return Record{}, ErrUnavailable
}
