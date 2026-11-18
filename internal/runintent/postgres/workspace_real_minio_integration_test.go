package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/workspace"
	"github.com/avaargsh/agent-control-panel/internal/workspace/s3blob"
)

// minioDropACK simulates the S3 PUT ACK being lost after the REAL MinIO
// server has persisted and re-served the correct scoped object bytes.
// This adapter is test-only and does not alter the production S3 client.
type minioDropACK struct {
	store       *s3blob.Store
	putAttempts int
}

func (f *minioDropACK) Upload(
	ctx context.Context, tenant, workspaceID, path string, contents io.Reader,
) (workspace.Asset, error) {
	f.putAttempts++
	_, err := f.store.Upload(ctx, tenant, workspaceID, path, contents)
	if err != nil {
		return workspace.Asset{}, err
	}
	return workspace.Asset{}, errors.New("injected: real MinIO PUT completed; ACK lost before ACP Stage")
}

func (f *minioDropACK) VerifyAsset(
	ctx context.Context, tenant, workspaceID string, asset workspace.Asset,
) error {
	return f.store.VerifyAsset(ctx, tenant, workspaceID, asset)
}

// TestWorkspaceRealMinIOPGReconcile is opt-in and requires an ACTUAL MinIO
// endpoint plus PostgreSQL. The MinIO bucket is initialized beforehand by
// TestMinIOBackend in the controlled workflow. This is NOT a mock-HTTP test
// and does not prove Cell process termination, production IAM, or Object Lock.
func TestWorkspaceRealMinIOPGReconcile(t *testing.T) {
	endpoint := os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires disposable real MinIO endpoint")
	}
	access := os.Getenv("S3BLOB_MINIO_TEST_ACCESS_KEY")
	secret := os.Getenv("S3BLOB_MINIO_TEST_SECRET_KEY")
	if access == "" || secret == "" {
		t.Fatal("MinIO credentials not configured for opt-in test")
	}
	store, err := s3blob.New(s3blob.Config{
		Endpoint: endpoint, Bucket: "research-artifacts", Region: "us-east-1",
		AccessKey: access, SecretKey: secret, AllowHTTPForTests: true,
	})
	if err != nil {
		t.Fatalf("construct real MinIO byte-verifier: %v", err)
	}
	repo, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repo, 98401)
	if _, _, err := repo.OpenWorkspace(ctx, lock); err != nil {
		t.Fatalf("create pinned Workspace: %v", err)
	}

	report := []byte("A scoped research report reopened after MinIO accepted PUT but the ACP ACK was lost.")
	sha := sha256.Sum256(report)
	asset := workspace.Asset{
		Path:      "reports/real-minio-research.md",
		Digest:    "sha256:" + hex.EncodeToString(sha[:]),
		SizeBytes: int64(len(report)),
	}
	intent := WorkspaceUploadInput{IntentID: "minio-lost-ack-report", Asset: asset, LeaseSeconds: 300}
	network := &minioDropACK{store: store}
	if _, err := repo.UploadWorkspaceObject(ctx, lock, intent, bytes.NewReader(report), network); !errors.Is(err, ErrUploadOutcomeUnknown) {
		t.Fatalf("real S3 PUT with lost ACK must remain UNKNOWN, got %v", err)
	}
	if network.putAttempts != 1 {
		t.Fatalf("expected one real MinIO write, got %d", network.putAttempts)
	}
	var unknown, prematureStages int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM workspace_upload_observations WHERE disposition='UNKNOWN'").
		Scan(&unknown); err != nil || unknown != 1 {
		t.Fatalf("lost ACK not journaled UNKNOWN: count=%d err=%v", unknown, err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_stages").
		Scan(&prematureStages); err != nil || prematureStages != 0 {
		t.Fatalf("created verified Stage before lost ACK reconciliation: count=%d err=%v", prematureStages, err)
	}

	// A fresh ACP repository instance performs a remote signed GET, hashes
	// the actual bytes, and idempotently creates the Stage evidence.
	restarted := New(pool)
	stage, err := restarted.ReconcileWorkspaceUpload(ctx, lock, intent.IntentID, store)
	if err != nil || stage.Asset != asset || stage.StageID != intent.IntentID {
		t.Fatalf("fresh repository did not verify real MinIO bytes: %+v err=%v", stage, err)
	}
	// A duplicate upload must reconcile and MUST NOT issue a second PUT.
	replayed, err := restarted.UploadWorkspaceObject(ctx, lock, intent, bytes.NewReader(report), network)
	if err != nil || replayed != stage || network.putAttempts != 1 {
		t.Fatalf("lost ACK replay issued another network PUT or changed stage: stage=%+v err=%v put=%d", replayed, err, network.putAttempts)
	}
	input := WorkspaceCommitInput{
		CommitID: "minio-report-commit", ExpectedRevision: 0,
		Assets: []workspace.Asset{asset},
	}
	receipt, err := restarted.CommitStagedWorkspace(ctx, lock, input, store)
	if err != nil || receipt.Revision != 1 {
		t.Fatalf("verified real MinIO data did not commit: %+v err=%v", receipt, err)
	}
	readBack, err := New(pool).ReadVerifiedWorkspaceAsset(ctx, lock, asset.Path, store)
	if err != nil || !bytes.Equal(report, readBack) {
		t.Fatalf("reopen actual MinIO Workspace report: %q err=%v", readBack, err)
	}
	if replayReceipt, err := New(pool).CommitStagedWorkspace(ctx, lock, input, nil); err != nil || replayReceipt != receipt {
		t.Fatalf("PG commit ACK-loss replay changed immutable receipt: %+v err=%v", replayReceipt, err)
	}
	if err := store.VerifyAsset(ctx, "tenant-other", lock.WorkspaceID, asset); !errors.Is(err, s3blob.ErrObjectMissing) {
		t.Fatalf("real MinIO allowed cross-tenant content-address lookup: %v", err)
	}
	foreign := lock
	foreign.TenantID = "tenant-other"
	if _, err := New(pool).ReadVerifiedWorkspaceAsset(ctx, foreign, asset.Path, store); !errors.Is(err, ErrWorkspaceScope) {
		t.Fatalf("forged ACP lock was accepted: %v", err)
	}
	var stageCount, refCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_stages").Scan(&stageCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_commit_refs").Scan(&refCount); err != nil {
		t.Fatal(err)
	}
	if stageCount != 1 || refCount != 1 {
		t.Fatalf("missing or duplicated Stage/retention evidence: stages=%d refs=%d", stageCount, refCount)
	}
}
