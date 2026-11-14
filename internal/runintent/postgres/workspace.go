package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/avaargsh/agent-control-panel/internal/researchlock"
	"github.com/avaargsh/agent-control-panel/internal/workspace"
	"github.com/jackc/pgx/v5"
)

var (
	ErrWorkspaceScope            = errors.New("workspace scope or pinned RunIntent mismatch")
	ErrWorkspaceNotFound         = errors.New("workspace not found")
	ErrWorkspaceRevisionConflict = errors.New("stale workspace manifest revision")
	ErrWorkspaceReplayConflict   = errors.New("workspace commit id reused with different content")
	ErrWorkspaceUnverifiedAsset  = errors.New("workspace asset lacks trusted object verification")
)

// Workspace is ACP-owned persistent metadata. Assets are not stored in this row.
type Workspace struct {
	TenantID         string
	WorkspaceID      string
	OwnerPrincipalID string
	Revision         int64
}

type WorkspaceCommitInput struct {
	CommitID         string
	ExpectedRevision int64
	Assets           []workspace.Asset
}

type WorkspaceCommitReceipt struct {
	TenantID         string
	WorkspaceID      string
	OwnerPrincipalID string
	CommitID         string
	Revision         int64
	PreviousRevision int64
	RunIntentID      string
	SessionID        string
	ArtifactDigest   string
	ManifestDigest   string
}

// AssetVerifier must be a trusted server-side adapter for immutable object
// bytes in the same tenant/Workspace scope. This repository provides no S3
// adapter; unverified nonempty manifests fail closed.
type AssetVerifier interface {
	VerifyAsset(context.Context, string, string, workspace.Asset) error
}

func workspaceTransaction(ctx context.Context, tx pgx.Tx, lock researchlock.Lock) error {
	if err := lock.Validate(); err != nil || !workspace.ValidID(lock.WorkspaceID) {
		return ErrWorkspaceScope
	}
	// These GUCs are solely RLS defense-in-depth; a trusted caller must first
	// authenticate the principal and obtain the pinned lock server-side.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true), set_config('app.principal_id',$2,true)", lock.TenantID, lock.PrincipalID); err != nil {
		return fmt.Errorf("bind workspace transaction principal: %w", err)
	}
	stored, found, err := readCapabilityLock(ctx, tx, lock.TenantID, lock.RunIntentID)
	if err != nil {
		return err
	}
	if !found || stored != lock {
		return ErrWorkspaceScope
	}
	return nil
}

func (r *Repository) OpenWorkspace(ctx context.Context, lock researchlock.Lock) (Workspace, bool, error) {
	if r == nil || r.pool == nil {
		return Workspace{}, false, ErrWorkspaceScope
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Workspace{}, false, fmt.Errorf("begin Workspace create: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := workspaceTransaction(ctx, tx, lock); err != nil {
		return Workspace{}, false, err
	}
	var state Workspace
	err = tx.QueryRow(ctx, `
		INSERT INTO research_workspaces (tenant_id, workspace_id, owner_principal_id)
		VALUES ($1,$2,$3)
		ON CONFLICT (tenant_id,workspace_id) DO NOTHING
		RETURNING tenant_id,workspace_id,owner_principal_id,manifest_revision
	`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID).
		Scan(&state.TenantID, &state.WorkspaceID, &state.OwnerPrincipalID, &state.Revision)
	inserted := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
			SELECT tenant_id,workspace_id,owner_principal_id,manifest_revision
			FROM research_workspaces
			WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3
		`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID).
			Scan(&state.TenantID, &state.WorkspaceID, &state.OwnerPrincipalID, &state.Revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return Workspace{}, false, ErrWorkspaceScope
		}
	}
	if err != nil {
		return Workspace{}, false, fmt.Errorf("open Workspace: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Workspace{}, false, fmt.Errorf("commit Workspace identity: %w", err)
	}
	return state, inserted, nil
}

func readWorkspace(ctx context.Context, tx pgx.Tx, lock researchlock.Lock) (Workspace, error) {
	var state Workspace
	err := tx.QueryRow(ctx, `
		SELECT tenant_id,workspace_id,owner_principal_id,manifest_revision
		FROM research_workspaces
		WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3
	`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID).
		Scan(&state.TenantID, &state.WorkspaceID, &state.OwnerPrincipalID, &state.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return Workspace{}, ErrWorkspaceNotFound
	}
	if err != nil {
		return Workspace{}, fmt.Errorf("read Workspace: %w", err)
	}
	if state.Revision < 0 {
		return Workspace{}, ErrCorruptRecord
	}
	return state, nil
}

// ReadWorkspaceSnapshot reconstructs persistent manifest metadata using a new
// database transaction. It does not fetch or cryptographically verify blobs.
func (r *Repository) ReadWorkspaceSnapshot(ctx context.Context, lock researchlock.Lock) (Workspace, []workspace.Asset, error) {
	if r == nil || r.pool == nil {
		return Workspace{}, nil, ErrWorkspaceScope
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Workspace{}, nil, fmt.Errorf("begin Workspace snapshot read: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := workspaceTransaction(ctx, tx, lock); err != nil {
		return Workspace{}, nil, err
	}
	state, err := readWorkspace(ctx, tx, lock)
	if err != nil {
		return Workspace{}, nil, err
	}
	assets := []workspace.Asset{}
	if state.Revision > 0 {
		var raw, storedDigest string
		err = tx.QueryRow(ctx, `
			SELECT manifest::text,manifest_digest FROM workspace_manifest_commits
			WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3
			  AND manifest_revision=$4
		`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, state.Revision).
			Scan(&raw, &storedDigest)
		if errors.Is(err, pgx.ErrNoRows) {
			return Workspace{}, nil, ErrCorruptRecord
		}
		if err != nil {
			return Workspace{}, nil, fmt.Errorf("read Workspace manifest: %w", err)
		}
		if err := json.Unmarshal([]byte(raw), &assets); err != nil {
			return Workspace{}, nil, ErrCorruptRecord
		}
		_, digest, err := workspace.CanonicalManifest(assets)
		if err != nil || digest != storedDigest {
			return Workspace{}, nil, ErrCorruptRecord
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Workspace{}, nil, fmt.Errorf("commit Workspace snapshot read: %w", err)
	}
	return state, assets, nil
}

func scanWorkspaceReceipt(row pgx.Row) (WorkspaceCommitReceipt, error) {
	var receipt WorkspaceCommitReceipt
	err := row.Scan(&receipt.TenantID, &receipt.WorkspaceID, &receipt.OwnerPrincipalID,
		&receipt.CommitID, &receipt.Revision, &receipt.PreviousRevision,
		&receipt.RunIntentID, &receipt.SessionID, &receipt.ArtifactDigest, &receipt.ManifestDigest)
	return receipt, err
}

const selectWorkspaceReceipt = "tenant_id,workspace_id,owner_principal_id,commit_id,manifest_revision,previous_revision,source_run_intent_id::text,session_id,das_digest,manifest_digest"

func workspaceReceiptMatches(receipt WorkspaceCommitReceipt, lock researchlock.Lock, input WorkspaceCommitInput, digest string) bool {
	return receipt.TenantID == lock.TenantID &&
		receipt.WorkspaceID == lock.WorkspaceID &&
		receipt.OwnerPrincipalID == lock.PrincipalID &&
		receipt.CommitID == input.CommitID &&
		receipt.PreviousRevision == input.ExpectedRevision &&
		receipt.RunIntentID == lock.RunIntentID &&
		receipt.SessionID == lock.SessionID &&
		receipt.ArtifactDigest == lock.ArtifactDigest &&
		receipt.ManifestDigest == digest
}

// CommitWorkspace atomically increments one Workspace revision and appends an
// immutable receipt. Callers must supply a server-verified RunIntent lock.
func (r *Repository) CommitWorkspace(
	ctx context.Context, lock researchlock.Lock, input WorkspaceCommitInput, verifier AssetVerifier,
) (WorkspaceCommitReceipt, error) {
	if r == nil || r.pool == nil || !workspace.ValidID(input.CommitID) ||
		input.ExpectedRevision < 0 || input.ExpectedRevision >= math.MaxInt64 {
		return WorkspaceCommitReceipt{}, workspace.ErrInvalidManifest
	}
	manifest, digest, err := workspace.CanonicalManifest(input.Assets)
	if err != nil {
		return WorkspaceCommitReceipt{}, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return WorkspaceCommitReceipt{}, fmt.Errorf("begin Workspace CAS: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := workspaceTransaction(ctx, tx, lock); err != nil {
		return WorkspaceCommitReceipt{}, err
	}

	existing, err := scanWorkspaceReceipt(tx.QueryRow(ctx, `
		SELECT `+selectWorkspaceReceipt+` FROM workspace_manifest_commits
		WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3 AND commit_id=$4
	`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, input.CommitID))
	if err == nil {
		if !workspaceReceiptMatches(existing, lock, input, digest) {
			return WorkspaceCommitReceipt{}, ErrWorkspaceReplayConflict
		}
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return WorkspaceCommitReceipt{}, fmt.Errorf("read Workspace idempotency receipt: %w", err)
	}

	// Authenticate the pinned ACP scope before invoking the external object
	// verifier. Already committed same-key replays need no new object access.
	if len(input.Assets) > 0 && verifier == nil {
		return WorkspaceCommitReceipt{}, ErrWorkspaceUnverifiedAsset
	}
	for _, asset := range input.Assets {
		if err := verifier.VerifyAsset(ctx, lock.TenantID, lock.WorkspaceID, asset); err != nil {
			return WorkspaceCommitReceipt{}, ErrWorkspaceUnverifiedAsset
		}
	}

	var nextRevision int64
	err = tx.QueryRow(ctx, `
		UPDATE research_workspaces
		SET manifest_revision=manifest_revision+1
		WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3
		  AND manifest_revision=$4
		RETURNING manifest_revision
	`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, input.ExpectedRevision).Scan(&nextRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		// Concurrent identical CommitIDs may both miss the first lookup.
		// A loser waits on the Workspace CAS row, then observes the winner's
		// committed receipt in a fresh READ COMMITTED statement.
		replayed, lookupErr := scanWorkspaceReceipt(tx.QueryRow(ctx, `
			SELECT `+selectWorkspaceReceipt+` FROM workspace_manifest_commits
			WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3 AND commit_id=$4
		`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, input.CommitID))
		if lookupErr == nil {
			if !workspaceReceiptMatches(replayed, lock, input, digest) {
				return WorkspaceCommitReceipt{}, ErrWorkspaceReplayConflict
			}
			return replayed, nil
		}
		if !errors.Is(lookupErr, pgx.ErrNoRows) {
			return WorkspaceCommitReceipt{}, fmt.Errorf("inspect concurrent Workspace replay: %w", lookupErr)
		}
		return WorkspaceCommitReceipt{}, ErrWorkspaceRevisionConflict
	}
	if err != nil {
		return WorkspaceCommitReceipt{}, fmt.Errorf("CAS Workspace manifest revision: %w", err)
	}

	receipt, err := scanWorkspaceReceipt(tx.QueryRow(ctx, `
		INSERT INTO workspace_manifest_commits (
			tenant_id,workspace_id,owner_principal_id,manifest_revision,previous_revision,commit_id,
			source_run_intent_id,session_id,das_digest,manifest_digest,manifest
		) VALUES ($1,$2,$3,$4,$5,$6,$7::uuid,$8,$9,$10,$11::jsonb)
		RETURNING `+selectWorkspaceReceipt,
		lock.TenantID, lock.WorkspaceID, lock.PrincipalID, nextRevision, input.ExpectedRevision,
		input.CommitID, lock.RunIntentID, lock.SessionID, lock.ArtifactDigest, digest, string(manifest),
	))
	if err != nil {
		return WorkspaceCommitReceipt{}, fmt.Errorf("insert Workspace manifest receipt: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return WorkspaceCommitReceipt{}, fmt.Errorf("commit Workspace CAS: %w", err)
	}
	return receipt, nil
}

// WorkspaceAssetReader is the trusted object-store read interface. The adapter
// must check actual bytes, tenant/Workspace namespace, size and SHA256.
type WorkspaceAssetReader interface {
	ReadAsset(context.Context, string, string, workspace.Asset) ([]byte, error)
}

var ErrWorkspaceAssetNotFound = errors.New("asset is absent from committed Workspace manifest")

// ReadVerifiedWorkspaceAsset first authenticates the pinned ACP identity and
// loads an immutable committed manifest, then obtains the blob through a
// trusted byte-verifying object-store adapter. Callers MUST derive the Lock
// from server-side verified principal/release state; this method is not an
// HTTP authentication boundary.
func (r *Repository) ReadVerifiedWorkspaceAsset(
	ctx context.Context, lock researchlock.Lock, logicalPath string, reader WorkspaceAssetReader,
) ([]byte, error) {
	if reader == nil || logicalPath == "" {
		return nil, ErrWorkspaceUnverifiedAsset
	}
	_, assets, err := r.ReadWorkspaceSnapshot(ctx, lock)
	if err != nil {
		return nil, err
	}
	for _, asset := range assets {
		if asset.Path == logicalPath {
			return reader.ReadAsset(ctx, lock.TenantID, lock.WorkspaceID, asset)
		}
	}
	return nil, ErrWorkspaceAssetNotFound
}
