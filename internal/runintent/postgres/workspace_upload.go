package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/researchlock"
	"github.com/avaargsh/agent-control-panel/internal/workspace"
	"github.com/jackc/pgx/v5"
)

var (
	ErrUploadIntentConflict = errors.New("Workspace upload intent ID reused for different asset or DAS identity")
	ErrUploadIntentExpired  = errors.New("Workspace upload intent expired before verification")
	ErrUploadIntentMissing  = errors.New("Workspace upload intent not found")
	ErrUploadOutcomeUnknown = errors.New("Workspace S3 upload outcome UNKNOWN; reconcile before committing")
	ErrUploadPayloadMismatch = errors.New("upload stream digest/size does not match predeclared Workspace asset")
)

// WorkspaceUploadInput describes an immutable expected object *before* any
// side-effect. The expected SHA256 and size are supplied by a trusted caller;
// the data plane checks them again after uploading or reconnecting.
type WorkspaceUploadInput struct {
	IntentID     string
	Asset        workspace.Asset
	LeaseSeconds int64
}

type WorkspaceUploadIntent struct {
	TenantID         string
	WorkspaceID      string
	OwnerPrincipalID string
	IntentID         string
	RunIntentID      string
	SessionID        string
	ArtifactDigest   string
	Asset            workspace.Asset
	LeaseSeconds     int64
	CreatedAt        time.Time
	ExpiresAt        time.Time
}

// WorkspaceObjectUploader is implemented by trusted signed object-store
// adapters. The worker MUST keep credentials private, not in Agent tooling.
type WorkspaceObjectUploader interface {
	AssetVerifier
	Upload(context.Context, string, string, string, io.Reader) (workspace.Asset, error)
}

const selectWorkspaceUploadIntent = "tenant_id,workspace_id,owner_principal_id,intent_id,source_run_intent_id::text,session_id,das_digest,asset_path,artifact_digest,size_bytes,lease_seconds,created_at,expires_at"

func scanWorkspaceUploadIntent(row pgx.Row) (WorkspaceUploadIntent, error) {
	var v WorkspaceUploadIntent
	err := row.Scan(&v.TenantID, &v.WorkspaceID, &v.OwnerPrincipalID, &v.IntentID,
		&v.RunIntentID, &v.SessionID, &v.ArtifactDigest, &v.Asset.Path, &v.Asset.Digest,
		&v.Asset.SizeBytes, &v.LeaseSeconds, &v.CreatedAt, &v.ExpiresAt)
	return v, err
}
func uploadIntentMatches(v WorkspaceUploadIntent, lock researchlock.Lock, in WorkspaceUploadInput) bool {
	return v.TenantID == lock.TenantID && v.WorkspaceID == lock.WorkspaceID &&
		v.OwnerPrincipalID == lock.PrincipalID && v.RunIntentID == lock.RunIntentID &&
		v.SessionID == lock.SessionID && v.ArtifactDigest == lock.ArtifactDigest &&
		v.IntentID == in.IntentID && v.Asset == in.Asset && v.LeaseSeconds == in.LeaseSeconds
}

// BeginWorkspaceUpload is the durable local transaction barrier. A caller
// MUST commit this operation before performing any S3 PUT.
func (r *Repository) BeginWorkspaceUpload(ctx context.Context, lock researchlock.Lock, in WorkspaceUploadInput) (WorkspaceUploadIntent, bool, error) {
	if r == nil || r.pool == nil || !workspace.ValidID(in.IntentID) || in.LeaseSeconds < 1 || in.LeaseSeconds > 86400 || in.Asset.SizeBytes > 8<<20 {
		return WorkspaceUploadIntent{}, false, workspace.ErrInvalidManifest
	}
	if _, _, err := workspace.CanonicalManifest([]workspace.Asset{in.Asset}); err != nil {
		return WorkspaceUploadIntent{}, false, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return WorkspaceUploadIntent{}, false, fmt.Errorf("begin upload intent: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := workspaceTransaction(ctx, tx, lock); err != nil {
		return WorkspaceUploadIntent{}, false, err
	}
	if _, err := readWorkspace(ctx, tx, lock); err != nil {
		return WorkspaceUploadIntent{}, false, err
	}
	v, err := scanWorkspaceUploadIntent(tx.QueryRow(ctx, `INSERT INTO workspace_upload_intents (
		tenant_id,workspace_id,owner_principal_id,intent_id,source_run_intent_id,session_id,
		das_digest,asset_path,artifact_digest,size_bytes,lease_seconds,expires_at
	) VALUES ($1,$2,$3,$4,$5::uuid,$6,$7,$8,$9,$10,$11,
		clock_timestamp()+($11::bigint*interval '1 second'))
	ON CONFLICT (tenant_id,workspace_id,intent_id) DO NOTHING RETURNING `+selectWorkspaceUploadIntent,
		lock.TenantID, lock.WorkspaceID, lock.PrincipalID, in.IntentID, lock.RunIntentID,
		lock.SessionID, lock.ArtifactDigest, in.Asset.Path, in.Asset.Digest, in.Asset.SizeBytes, in.LeaseSeconds))
	created := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		v, err = scanWorkspaceUploadIntent(tx.QueryRow(ctx, `SELECT `+selectWorkspaceUploadIntent+`
			FROM workspace_upload_intents WHERE tenant_id=$1 AND workspace_id=$2
			 AND owner_principal_id=$3 AND intent_id=$4`,
			lock.TenantID, lock.WorkspaceID, lock.PrincipalID, in.IntentID))
	}
	if err != nil {
		return WorkspaceUploadIntent{}, false, fmt.Errorf("read persisted upload intent: %w", err)
	}
	if !uploadIntentMatches(v, lock, in) {
		return WorkspaceUploadIntent{}, false, ErrUploadIntentConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return WorkspaceUploadIntent{}, false, fmt.Errorf("commit upload intent: %w", err)
	}
	return v, created, nil
}

func (r *Repository) readUploadIntent(ctx context.Context, lock researchlock.Lock, intentID string) (WorkspaceUploadIntent, error) {
	if r == nil || r.pool == nil || !workspace.ValidID(intentID) {
		return WorkspaceUploadIntent{}, workspace.ErrInvalidManifest
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return WorkspaceUploadIntent{}, fmt.Errorf("begin upload read: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := workspaceTransaction(ctx, tx, lock); err != nil {
		return WorkspaceUploadIntent{}, err
	}
	v, err := scanWorkspaceUploadIntent(tx.QueryRow(ctx, `SELECT `+selectWorkspaceUploadIntent+`
		FROM workspace_upload_intents WHERE tenant_id=$1 AND workspace_id=$2
			AND owner_principal_id=$3 AND intent_id=$4`,
		lock.TenantID, lock.WorkspaceID, lock.PrincipalID, intentID))
	if errors.Is(err, pgx.ErrNoRows) {
		return WorkspaceUploadIntent{}, ErrUploadIntentMissing
	}
	if err != nil {
		return WorkspaceUploadIntent{}, fmt.Errorf("read upload intent: %w", err)
	}
	if v.RunIntentID != lock.RunIntentID || v.SessionID != lock.SessionID ||
		v.ArtifactDigest != lock.ArtifactDigest {
		return WorkspaceUploadIntent{}, ErrWorkspaceScope
	}
	if err := tx.Commit(ctx); err != nil {
		return WorkspaceUploadIntent{}, fmt.Errorf("commit upload intent read: %w", err)
	}
	return v, nil
}

// appendUploadObservation records an immutable local observation. UNKNOWN is
// not equivalent to FAILED, and this never attempts a S3 delete.
func (r *Repository) appendUploadObservation(ctx context.Context, lock researchlock.Lock, intentID, disposition string) error {
	if disposition != "UNKNOWN" && disposition != "VERIFIED" {
		return workspace.ErrInvalidManifest
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin upload observation: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := workspaceTransaction(ctx, tx, lock); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO workspace_upload_observations(
		tenant_id,workspace_id,owner_principal_id,intent_id,disposition)
		VALUES ($1,$2,$3,$4,$5)`,
		lock.TenantID, lock.WorkspaceID, lock.PrincipalID, intentID, disposition); err != nil {
		return fmt.Errorf("append upload disposition: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit upload observation: %w", err)
	}
	return nil
}

// UploadWorkspaceObject begins with a durable intent, performs a single
// trusted signed PUT, then re-verifies actual bytes. Any transport/byte/stage
// error stays UNKNOWN; callers must reconcile, never blindly retry effects.
func (r *Repository) UploadWorkspaceObject(ctx context.Context, lock researchlock.Lock, in WorkspaceUploadInput, content io.Reader, uploader WorkspaceObjectUploader) (BlobStage, error) {
	if content == nil || uploader == nil {
		return BlobStage{}, ErrWorkspaceUnverifiedAsset
	}
	// Validate the actual stream before a remote PUT. A backend that keys
	// objects by its observed digest could otherwise create an untracked
	// wrong-digest object when the declared request does not match.
	data, err := io.ReadAll(io.LimitReader(content, (8<<20)+1))
	if err != nil || len(data) > 8<<20 {
		return BlobStage{}, ErrUploadPayloadMismatch
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != in.Asset.SizeBytes || "sha256:"+hex.EncodeToString(sum[:]) != in.Asset.Digest {
		return BlobStage{}, ErrUploadPayloadMismatch
	}
	_, created, err := r.BeginWorkspaceUpload(ctx, lock, in)
	if err != nil {
		return BlobStage{}, err
	}
	// An existing intent represents a possibly completed remote PUT.
	// NEVER issue a second blind PUT; use a read-only byte reconciliation.
	if !created {
		return r.ReconcileWorkspaceUpload(ctx, lock, in.IntentID, uploader)
	}
	intent, err := r.readUploadIntent(ctx, lock, in.IntentID)
	if err != nil {
		return BlobStage{}, err
	}
	if !time.Now().Before(intent.ExpiresAt) {
		return BlobStage{}, ErrUploadIntentExpired
	}
	actual, uploadErr := uploader.Upload(ctx, lock.TenantID, lock.WorkspaceID, in.Asset.Path, bytes.NewReader(data))
	if uploadErr != nil || actual != in.Asset {
		if err := r.appendUploadObservation(ctx, lock, in.IntentID, "UNKNOWN"); err != nil {
			return BlobStage{}, errors.Join(ErrUploadOutcomeUnknown, err)
		}
		return BlobStage{}, ErrUploadOutcomeUnknown
	}
	return r.ReconcileWorkspaceUpload(ctx, lock, in.IntentID, uploader)
}

// ReconcileWorkspaceUpload never PUTs again. It re-reads and hashes the
// server-derived scoped object and only then writes idempotent Stage evidence.
func (r *Repository) ReconcileWorkspaceUpload(ctx context.Context, lock researchlock.Lock, intentID string, verifier AssetVerifier) (BlobStage, error) {
	if verifier == nil {
		return BlobStage{}, ErrWorkspaceUnverifiedAsset
	}
	intent, err := r.readUploadIntent(ctx, lock, intentID)
	if err != nil {
		return BlobStage{}, err
	}
	if !time.Now().Before(intent.ExpiresAt) {
		return BlobStage{}, ErrUploadIntentExpired
	}
	if err := verifier.VerifyAsset(ctx, lock.TenantID, lock.WorkspaceID, intent.Asset); err != nil {
		if e := r.appendUploadObservation(ctx, lock, intentID, "UNKNOWN"); e != nil {
			return BlobStage{}, errors.Join(ErrUploadOutcomeUnknown, e)
		}
		return BlobStage{}, ErrUploadOutcomeUnknown
	}
	if !time.Now().Before(intent.ExpiresAt) {
		return BlobStage{}, ErrUploadIntentExpired
	}
	stage, _, err := r.StageWorkspaceAsset(ctx, lock, intentID, intent.Asset, intent.LeaseSeconds, verifier)
	if err != nil {
		if e := r.appendUploadObservation(ctx, lock, intentID, "UNKNOWN"); e != nil {
			return BlobStage{}, errors.Join(ErrUploadOutcomeUnknown, e)
		}
		return BlobStage{}, ErrUploadOutcomeUnknown
	}
	if err := r.appendUploadObservation(ctx, lock, intentID, "VERIFIED"); err != nil {
		return BlobStage{}, errors.Join(ErrUploadOutcomeUnknown, err)
	}
	return stage, nil
}
