package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/avaargsh/agent-control-panel/internal/researchlock"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
	"github.com/jackc/pgx/v5"
)

// ErrInvalidCapabilityLock means the proposed lock cannot be attached to the
// authenticated, ACP-owned RunIntent. The lock itself carries no authority.
var ErrInvalidCapabilityLock = errors.New("invalid RunIntent capability lock")

// CreatePinned atomically commits a RunIntent, its immutable DAS release lock
// and the creation Outbox event, or commits none. Caller MUST authenticate the
// principal and obtain release/entitlement evidence from trusted stores first.
func (r *Repository) CreatePinned(
	ctx context.Context, intent runintent.Intent, event Event, lock researchlock.Lock,
) (runintent.Intent, bool, error) {
	return r.create(ctx, intent, event, &lock)
}

func validIntentCapabilityLock(intent runintent.Intent, lock researchlock.Lock) bool {
	return lock.Validate() == nil &&
		lock.TenantID == intent.TenantID &&
		lock.PrincipalID == intent.PrincipalID &&
		lock.RunIntentID == intent.ID &&
		lock.AgentReleaseID == intent.ReleaseID &&
		lock.SessionID == intent.SessionID
}

const selectCapabilityLockColumns = "tenant_id, principal_id, run_intent_id::text, agent_release_id, workspace_id, session_id, package_id, package_version, artifact_digest, subscription_id, policy_revision"

func readCapabilityLock(ctx context.Context, tx pgx.Tx, tenantID, intentID string) (researchlock.Lock, bool, error) {
	var lock researchlock.Lock
	err := tx.QueryRow(ctx, "SELECT "+selectCapabilityLockColumns+
		" FROM run_capability_locks WHERE tenant_id=$1 AND run_intent_id=$2::uuid",
		tenantID, intentID,
	).Scan(
		&lock.TenantID, &lock.PrincipalID, &lock.RunIntentID, &lock.AgentReleaseID,
		&lock.WorkspaceID, &lock.SessionID, &lock.PackageID, &lock.Version,
		&lock.ArtifactDigest, &lock.SubscriptionID, &lock.PolicyRevision,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return researchlock.Lock{}, false, nil
	}
	if err != nil {
		return researchlock.Lock{}, false, fmt.Errorf("read RunIntent DAS lock: %w", err)
	}
	if err := lock.Validate(); err != nil {
		return researchlock.Lock{}, false, fmt.Errorf("%w: %v", ErrCorruptRecord, err)
	}
	return lock, true, nil
}

func compareCapabilityReplay(ctx context.Context, tx pgx.Tx, existing runintent.Intent, proposed *researchlock.Lock) error {
	stored, found, err := readCapabilityLock(ctx, tx, existing.TenantID, existing.ID)
	if err != nil {
		return err
	}
	if proposed == nil {
		if found {
			return ErrIdempotencyConflict
		}
		return nil
	}
	if !found {
		return ErrIdempotencyConflict
	}
	// A duplicate submission can have a newly generated candidate Intent ID.
	// Compare the existing canonical Intent ID while retaining every other
	// immutable launch identity in the proposed binding.
	normalized := *proposed
	normalized.RunIntentID = existing.ID
	if err := researchlock.CheckReplay(stored, normalized); err != nil {
		if errors.Is(err, researchlock.ErrReplayConflict) {
			return ErrIdempotencyConflict
		}
		return fmt.Errorf("%w: %v", ErrInvalidCapabilityLock, err)
	}
	return nil
}

func insertCapabilityLock(ctx context.Context, tx pgx.Tx, lock researchlock.Lock) error {
	_, err := tx.Exec(ctx, `INSERT INTO run_capability_locks (
		run_intent_id, tenant_id, principal_id, agent_release_id, workspace_id,
		session_id, package_id, package_version, artifact_digest, subscription_id, policy_revision
	) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		lock.RunIntentID, lock.TenantID, lock.PrincipalID, lock.AgentReleaseID,
		lock.WorkspaceID, lock.SessionID, lock.PackageID, lock.Version,
		lock.ArtifactDigest, lock.SubscriptionID, lock.PolicyRevision,
	)
	return err
}

// GetCapabilityLock returns only a pinned reference belonging to the trusted
// tenant scope. Caller authentication must precede the repository call.
func (r *Repository) GetCapabilityLock(ctx context.Context, tenantID, intentID string) (researchlock.Lock, error) {
	if r == nil || r.pool == nil || tenantID == "" || intentID == "" {
		return researchlock.Lock{}, ErrInvalidCapabilityLock
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return researchlock.Lock{}, fmt.Errorf("begin capability lock read: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		return researchlock.Lock{}, fmt.Errorf("bind capability read tenant: %w", err)
	}
	lock, found, err := readCapabilityLock(ctx, tx, tenantID, intentID)
	if err != nil {
		return researchlock.Lock{}, err
	}
	if !found {
		return researchlock.Lock{}, ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return researchlock.Lock{}, fmt.Errorf("commit capability lock read: %w", err)
	}
	return lock, nil
}
