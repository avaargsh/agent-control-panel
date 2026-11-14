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
	ErrBlobStageConflict = errors.New("Workspace blob stage ID reused for different evidence")
	ErrBlobStageMissing  = errors.New("Workspace blob has no unexpired verified stage")
)

// BlobStage is immutable evidence of scoped object verification at a point
// in time, not proof of permanent backend retention or caller authorization.
type BlobStage struct {
	TenantID         string
	WorkspaceID      string
	OwnerPrincipalID string
	StageID          string
	RunIntentID      string
	SessionID        string
	ArtifactDigest   string
	Asset            workspace.Asset
	LeaseSeconds     int64
	CreatedAt        time.Time
	ExpiresAt        time.Time
}

const selectBlobStage = "tenant_id,workspace_id,owner_principal_id,stage_id,source_run_intent_id::text,session_id,das_digest,asset_path,artifact_digest,size_bytes,lease_seconds,created_at,expires_at"

func scanBlobStage(row pgx.Row) (BlobStage, error) {
	var stage BlobStage
	err := row.Scan(&stage.TenantID, &stage.WorkspaceID, &stage.OwnerPrincipalID, &stage.StageID, &stage.RunIntentID,
		&stage.SessionID, &stage.ArtifactDigest, &stage.Asset.Path, &stage.Asset.Digest, &stage.Asset.SizeBytes,
		&stage.LeaseSeconds, &stage.CreatedAt, &stage.ExpiresAt)
	return stage, err
}

func blobStageMatches(stage BlobStage, lock researchlock.Lock, stageID string, asset workspace.Asset, leaseSeconds int64) bool {
	return stage.TenantID == lock.TenantID && stage.WorkspaceID == lock.WorkspaceID &&
		stage.OwnerPrincipalID == lock.PrincipalID && stage.StageID == stageID &&
		stage.RunIntentID == lock.RunIntentID && stage.SessionID == lock.SessionID &&
		stage.ArtifactDigest == lock.ArtifactDigest && stage.Asset == asset &&
		stage.LeaseSeconds == leaseSeconds
}

// StageWorkspaceAsset writes immutable stage evidence only after a trusted
// verifier reads and checks actual object bytes. A replay never renews a lease.
func (r *Repository) StageWorkspaceAsset(ctx context.Context, lock researchlock.Lock,
	stageID string, asset workspace.Asset, leaseSeconds int64, verifier AssetVerifier,
) (BlobStage, bool, error) {
	if r == nil || r.pool == nil || !workspace.ValidID(stageID) ||
		leaseSeconds < 1 || leaseSeconds > 86400 {
		return BlobStage{}, false, workspace.ErrInvalidManifest
	}
	if _, _, err := workspace.CanonicalManifest([]workspace.Asset{asset}); err != nil {
		return BlobStage{}, false, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return BlobStage{}, false, fmt.Errorf("begin blob stage: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := workspaceTransaction(ctx, tx, lock); err != nil {
		return BlobStage{}, false, err
	}
	if _, err := readWorkspace(ctx, tx, lock); err != nil {
		return BlobStage{}, false, err
	}
	existing, err := scanBlobStage(tx.QueryRow(ctx, `SELECT `+selectBlobStage+`
		FROM workspace_blob_stages WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3 AND stage_id=$4`,
		lock.TenantID, lock.WorkspaceID, lock.PrincipalID, stageID))
	if err == nil {
		if !blobStageMatches(existing, lock, stageID, asset, leaseSeconds) {
			return BlobStage{}, false, ErrBlobStageConflict
		}
		return existing, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return BlobStage{}, false, fmt.Errorf("lookup blob stage: %w", err)
	}
	if verifier == nil {
		return BlobStage{}, false, ErrWorkspaceUnverifiedAsset
	}
	if err := verifier.VerifyAsset(ctx, lock.TenantID, lock.WorkspaceID, asset); err != nil {
		return BlobStage{}, false, ErrWorkspaceUnverifiedAsset
	}
	staged, err := scanBlobStage(tx.QueryRow(ctx, `INSERT INTO workspace_blob_stages (
		tenant_id,workspace_id,owner_principal_id,stage_id,source_run_intent_id,session_id,
		das_digest,asset_path,artifact_digest,size_bytes,lease_seconds,expires_at
	) VALUES ($1,$2,$3,$4,$5::uuid,$6,$7,$8,$9,$10,$11,
		clock_timestamp()+($11::bigint * interval '1 second'))
	ON CONFLICT (tenant_id,workspace_id,stage_id) DO NOTHING
	RETURNING `+selectBlobStage, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, stageID,
		lock.RunIntentID, lock.SessionID, lock.ArtifactDigest, asset.Path, asset.Digest,
		asset.SizeBytes, leaseSeconds))
	created := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		staged, err = scanBlobStage(tx.QueryRow(ctx, `SELECT `+selectBlobStage+`
			FROM workspace_blob_stages WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3 AND stage_id=$4`,
			lock.TenantID, lock.WorkspaceID, lock.PrincipalID, stageID))
		if err == nil && !blobStageMatches(staged, lock, stageID, asset, leaseSeconds) {
			return BlobStage{}, false, ErrBlobStageConflict
		}
	}
	if err != nil {
		return BlobStage{}, false, fmt.Errorf("persist blob stage: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return BlobStage{}, false, fmt.Errorf("commit blob stage: %w", err)
	}
	return staged, created, nil
}

// ListExpiredBlobCandidates only observes expired provisional receipts and
// never deletes bytes. Every immutable manifest revision remains a retention
// barrier, including v6 receipts lacking a per-asset reference index.
func (r *Repository) ListExpiredBlobCandidates(ctx context.Context, lock researchlock.Lock, limit int) ([]BlobStage, error) {
	if r == nil || r.pool == nil || limit < 1 || limit > 100 {
		return nil, workspace.ErrInvalidManifest
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin orphan candidate query: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := workspaceTransaction(ctx, tx, lock); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+selectBlobStage+` FROM workspace_blob_stages s
		WHERE s.tenant_id=$1 AND s.workspace_id=$2 AND s.owner_principal_id=$3
		  AND s.expires_at<=clock_timestamp()
		  AND NOT EXISTS (SELECT 1 FROM workspace_blob_commit_refs ref
			  WHERE ref.tenant_id=s.tenant_id AND ref.workspace_id=s.workspace_id
			    AND ref.owner_principal_id=s.owner_principal_id AND ref.artifact_digest=s.artifact_digest)
		  AND NOT EXISTS (SELECT 1 FROM workspace_manifest_commits c
			  WHERE c.tenant_id=s.tenant_id AND c.workspace_id=s.workspace_id
			    AND c.owner_principal_id=s.owner_principal_id
			    AND c.manifest @> jsonb_build_array(jsonb_build_object('digest',s.artifact_digest)))
		ORDER BY s.created_at,s.stage_id LIMIT $4`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, limit)
	if err != nil {
		return nil, fmt.Errorf("query expired blob candidates: %w", err)
	}
	defer rows.Close()
	stages := make([]BlobStage, 0)
	for rows.Next() {
		stage, err := scanBlobStage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan expired stage: %w", err)
		}
		stages = append(stages, stage)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expired stages: %w", err)
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit candidate read: %w", err)
	}
	return stages, nil
}
