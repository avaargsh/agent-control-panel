package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/researchlock"
	"github.com/avaargsh/agent-control-panel/internal/workspace"
	"github.com/jackc/pgx/v5"
)

var (
	ErrGCClaimBusy   = errors.New("Workspace object has a live fenced GC claim")
	ErrGCStaleFence  = errors.New("Workspace GC holder or generation is stale or expired")
	ErrGCNotEligible = errors.New("Workspace object is not a reclaimable GC candidate")
)

// GCClaim is a database-only fenced observation, never a provider DELETE
// authorization. Generation is monotonically increasing across lease holders.
type GCClaim struct {
	TenantID         string
	WorkspaceID      string
	OwnerPrincipalID string
	ArtifactDigest   string
	HolderID         string
	Generation       int64
	LeaseSeconds     int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
	ExpiresAt        time.Time
}

const gcClaimColumns = "tenant_id,workspace_id,owner_principal_id,artifact_digest,holder_id,generation,lease_seconds,created_at,updated_at,expires_at"

func scanGCClaim(row pgx.Row) (GCClaim, error) {
	var v GCClaim
	err := row.Scan(&v.TenantID, &v.WorkspaceID, &v.OwnerPrincipalID,
		&v.ArtifactDigest, &v.HolderID, &v.Generation, &v.LeaseSeconds,
		&v.CreatedAt, &v.UpdatedAt, &v.ExpiresAt)
	return v, err
}

// lockGCWorkspace is the single serialization point for GC claims, new
// upload intents, new verified stages, and any manifest commit.
func lockGCWorkspace(ctx context.Context, tx pgx.Tx, lock researchlock.Lock) error {
	var revision int64
	err := tx.QueryRow(ctx, `
		SELECT manifest_revision FROM research_workspaces
		WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3
		FOR UPDATE
	`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrWorkspaceNotFound
	}
	if err != nil {
		return fmt.Errorf("lock Workspace GC serialization row: %w", err)
	}
	return nil
}

// assertNoActiveGC prevents a new stage, upload intent, or manifest reference
// being created during an active claim. Caller must hold the Workspace row
// FOR UPDATE or the existing manifest CAS UPDATE row lock.
func assertNoActiveGC(ctx context.Context, tx pgx.Tx, lock researchlock.Lock, digest string) error {
	var active bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM workspace_gc_claims
			WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3
			  AND artifact_digest=$4 AND expires_at > clock_timestamp()
		)
	`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, digest).Scan(&active); err != nil {
		return fmt.Errorf("read active Workspace GC claim: %w", err)
	}
	if active {
		return ErrGCClaimBusy
	}
	return nil
}

// gcEligible requires an expired verified Stage as positive evidence.
// EVERY historical v6+ manifest/ref blocks reclaim, as do fresh stages,
// active uploads, and expired upload intents with unresolved UNKNOWN bytes.
// No object is declared safe to delete based on this local predicate.
func gcEligible(ctx context.Context, tx pgx.Tx, lock researchlock.Lock, digest string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `
		SELECT
		  EXISTS (
		    SELECT 1 FROM workspace_blob_stages s
		    WHERE s.tenant_id=$1 AND s.workspace_id=$2
		      AND s.owner_principal_id=$3 AND s.artifact_digest=$4
		      AND s.expires_at <= clock_timestamp()
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM workspace_blob_stages s
		    WHERE s.tenant_id=$1 AND s.workspace_id=$2
		      AND s.owner_principal_id=$3 AND s.artifact_digest=$4
		      AND s.expires_at > clock_timestamp()
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM workspace_blob_commit_refs ref
		    WHERE ref.tenant_id=$1 AND ref.workspace_id=$2
		      AND ref.owner_principal_id=$3 AND ref.artifact_digest=$4
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM workspace_manifest_commits c
		    WHERE c.tenant_id=$1 AND c.workspace_id=$2
		      AND c.owner_principal_id=$3
		      AND c.manifest @> jsonb_build_array(jsonb_build_object('digest',$4::text))
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM workspace_upload_intents u
		    WHERE u.tenant_id=$1 AND u.workspace_id=$2
		      AND u.owner_principal_id=$3 AND u.artifact_digest=$4
		      AND (
		        u.expires_at > clock_timestamp() OR
		        COALESCE((
		          SELECT o.disposition FROM workspace_upload_observations o
		          WHERE o.tenant_id=u.tenant_id AND o.workspace_id=u.workspace_id
		            AND o.owner_principal_id=u.owner_principal_id
		            AND o.intent_id=u.intent_id
		          ORDER BY o.observation_id DESC LIMIT 1
		        ),'UNKNOWN') <> 'VERIFIED'
		      )
		  )
	`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, digest).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("inspect all historical GC retention barriers: %w", err)
	}
	return ok, nil
}

// gcIneligibilityReason records why this local candidate was declined. It
// never treats a missing upload ACK as a negative existence proof.
func gcIneligibilityReason(ctx context.Context, tx pgx.Tx, lock researchlock.Lock, digest string) (string, error) {
	var retained, unresolved bool
	err := tx.QueryRow(ctx, `
		SELECT
		  EXISTS (
		    SELECT 1 FROM workspace_blob_commit_refs ref
		    WHERE ref.tenant_id=$1 AND ref.workspace_id=$2
		      AND ref.owner_principal_id=$3 AND ref.artifact_digest=$4
		  ) OR EXISTS (
		    SELECT 1 FROM workspace_manifest_commits c
		    WHERE c.tenant_id=$1 AND c.workspace_id=$2
		      AND c.owner_principal_id=$3
		      AND c.manifest @> jsonb_build_array(jsonb_build_object('digest',$4::text))
		  ),
		  EXISTS (
		    SELECT 1 FROM workspace_upload_intents u
		    WHERE u.tenant_id=$1 AND u.workspace_id=$2
		      AND u.owner_principal_id=$3 AND u.artifact_digest=$4
		      AND (
		        u.expires_at > clock_timestamp() OR
		        COALESCE((
		          SELECT o.disposition FROM workspace_upload_observations o
		          WHERE o.tenant_id=u.tenant_id AND o.workspace_id=u.workspace_id
		            AND o.owner_principal_id=u.owner_principal_id
		            AND o.intent_id=u.intent_id
		          ORDER BY o.observation_id DESC LIMIT 1
		        ),'UNKNOWN') <> 'VERIFIED'
		      )
		  )
	`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, digest).Scan(&retained, &unresolved)
	if err != nil {
		return "", fmt.Errorf("classify GC retention or UNKNOWN: %w", err)
	}
	if retained {
		return "RETAINED", nil
	}
	if unresolved {
		return "UNKNOWN", nil
	}
	return "NOT_ELIGIBLE", nil
}

func appendGCObservation(ctx context.Context, tx pgx.Tx, lock researchlock.Lock,
	digest, holder string, generation int64, disposition string,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO workspace_gc_observations(
			tenant_id,workspace_id,owner_principal_id,artifact_digest,
			holder_id,generation,disposition
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID,
		digest, holder, generation, disposition)
	return err
}

func validateGCArgs(r *Repository, digest, holder string, leaseSeconds int64) error {
	if r == nil || r.pool == nil || !workspace.ValidDigest(digest) ||
		!workspace.ValidID(holder) || leaseSeconds < 1 || leaseSeconds > 300 {
		return workspace.ErrInvalidManifest
	}
	return nil
}

// ClaimWorkspaceBlob obtains a local, non-destructive lease on a proven
// expired Stage. The same live holder replays without extending its expiry.
// Another holder must wait for expiry and receives a fresh generation.
func (r *Repository) ClaimWorkspaceBlob(ctx context.Context, lock researchlock.Lock,
	digest, holder string, leaseSeconds int64,
) (GCClaim, error) {
	if err := validateGCArgs(r, digest, holder, leaseSeconds); err != nil {
		return GCClaim{}, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return GCClaim{}, fmt.Errorf("begin GC claim: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := workspaceTransaction(ctx, tx, lock); err != nil {
		return GCClaim{}, err
	}
	if err := lockGCWorkspace(ctx, tx, lock); err != nil {
		return GCClaim{}, err
	}
	eligible, err := gcEligible(ctx, tx, lock, digest)
	if err != nil {
		return GCClaim{}, err
	}
	if !eligible {
		reason, err := gcIneligibilityReason(ctx, tx, lock, digest)
		if err != nil {
			return GCClaim{}, err
		}
		if err := appendGCObservation(ctx, tx, lock, digest, holder, 0, reason); err != nil {
			return GCClaim{}, fmt.Errorf("record ineligible GC observation: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return GCClaim{}, err
		}
		return GCClaim{}, ErrGCNotEligible
	}

	existing, err := scanGCClaim(tx.QueryRow(ctx, `
		SELECT `+gcClaimColumns+` FROM workspace_gc_claims
		WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3 AND artifact_digest=$4
	`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, digest))
	hasExisting := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return GCClaim{}, fmt.Errorf("inspect existing GC holder: %w", err)
	}
	var live bool
	if hasExisting {
		if err := tx.QueryRow(ctx, `
			SELECT expires_at > clock_timestamp() FROM workspace_gc_claims
			WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3 AND artifact_digest=$4
		`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, digest).Scan(&live); err != nil {
			return GCClaim{}, err
		}
	}
	if live {
		if existing.HolderID != holder {
			return GCClaim{}, ErrGCClaimBusy
		}
		if err := tx.Commit(ctx); err != nil {
			return GCClaim{}, err
		}
		return existing, nil
	}
	claim, err := scanGCClaim(tx.QueryRow(ctx, `
		INSERT INTO workspace_gc_claims (
			tenant_id,workspace_id,owner_principal_id,artifact_digest,
			holder_id,generation,lease_seconds,expires_at
		) VALUES ($1,$2,$3,$4,$5,1,$6,clock_timestamp()+($6*interval '1 second'))
		ON CONFLICT (tenant_id,workspace_id,artifact_digest)
		DO UPDATE SET holder_id=EXCLUDED.holder_id,
		  generation=workspace_gc_claims.generation+1,
		  lease_seconds=EXCLUDED.lease_seconds,
		  updated_at=clock_timestamp(),
		  expires_at=clock_timestamp()+(EXCLUDED.lease_seconds*interval '1 second')
		WHERE workspace_gc_claims.expires_at <= clock_timestamp()
		RETURNING `+gcClaimColumns, lock.TenantID, lock.WorkspaceID,
		lock.PrincipalID, digest, holder, leaseSeconds))
	if errors.Is(err, pgx.ErrNoRows) {
		return GCClaim{}, ErrGCClaimBusy
	}
	if err != nil {
		return GCClaim{}, fmt.Errorf("acquire fenced GC claim: %w", err)
	}
	disposition := "ACQUIRED"
	if hasExisting {
		disposition = "RECLAIMED"
	}
	if err := appendGCObservation(ctx, tx, lock, digest, holder, claim.Generation, disposition); err != nil {
		return GCClaim{}, fmt.Errorf("append fenced GC claim audit: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return GCClaim{}, fmt.Errorf("commit fenced GC claim: %w", err)
	}
	return claim, nil
}

// RenewWorkspaceGCClaim advances the generation, fencing out the former
// token even if the same collector is renewing. It is NOT a delete permit.
func (r *Repository) RenewWorkspaceGCClaim(ctx context.Context, lock researchlock.Lock,
	digest, holder string, oldGeneration, leaseSeconds int64,
) (GCClaim, error) {
	if err := validateGCArgs(r, digest, holder, leaseSeconds); err != nil {
		return GCClaim{}, err
	}
	if oldGeneration <= 0 {
		return GCClaim{}, ErrGCStaleFence
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return GCClaim{}, fmt.Errorf("begin GC renew: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := workspaceTransaction(ctx, tx, lock); err != nil {
		return GCClaim{}, err
	}
	if err := lockGCWorkspace(ctx, tx, lock); err != nil {
		return GCClaim{}, err
	}
	eligible, err := gcEligible(ctx, tx, lock, digest)
	if err != nil {
		return GCClaim{}, err
	}
	if !eligible {
		return GCClaim{}, ErrGCNotEligible
	}
	claim, err := scanGCClaim(tx.QueryRow(ctx, `
		UPDATE workspace_gc_claims
		SET generation=generation+1, lease_seconds=$7,
		    updated_at=clock_timestamp(),
		    expires_at=clock_timestamp()+($7*interval '1 second')
		WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3
		  AND artifact_digest=$4 AND holder_id=$5 AND generation=$6
		  AND expires_at > clock_timestamp()
		RETURNING `+gcClaimColumns, lock.TenantID, lock.WorkspaceID, lock.PrincipalID,
		digest, holder, oldGeneration, leaseSeconds))
	if errors.Is(err, pgx.ErrNoRows) {
		return GCClaim{}, ErrGCStaleFence
	}
	if err != nil {
		return GCClaim{}, fmt.Errorf("renew fenced GC claim: %w", err)
	}
	if err := appendGCObservation(ctx, tx, lock, digest, holder, claim.Generation, "RENEWED"); err != nil {
		return GCClaim{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return GCClaim{}, err
	}
	return claim, nil
}

// CheckWorkspaceGCClaim rechecks the exact persisted generation, holder,
// deadline and historical retention while holding the same Workspace lock.
// Only a local observation; it MUST NOT be used as DeleteObject authority.
func (r *Repository) CheckWorkspaceGCClaim(ctx context.Context, lock researchlock.Lock,
	digest, holder string, generation int64,
) error {
	if err := validateGCArgs(r, digest, holder, 1); err != nil {
		return err
	}
	if generation <= 0 {
		return ErrGCStaleFence
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin GC validation: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := workspaceTransaction(ctx, tx, lock); err != nil {
		return err
	}
	if err := lockGCWorkspace(ctx, tx, lock); err != nil {
		return err
	}
	var active bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM workspace_gc_claims
			WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3
			  AND artifact_digest=$4 AND holder_id=$5 AND generation=$6
			  AND expires_at>clock_timestamp()
		)
	`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID,
		digest, holder, generation).Scan(&active); err != nil {
		return err
	}
	if !active {
		return ErrGCStaleFence
	}
	eligible, err := gcEligible(ctx, tx, lock, digest)
	if err != nil {
		return err
	}
	if !eligible {
		return ErrGCNotEligible
	}
	return tx.Commit(ctx)
}
