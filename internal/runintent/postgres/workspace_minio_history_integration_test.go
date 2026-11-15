package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/workspace"
	"github.com/avaargsh/agent-control-panel/internal/workspace/s3blob"
)

// TestWorkspaceRealMinIOHistoricalRetainedBytesPG proves, against actual
// PostgreSQL16 and a disposable real MinIO endpoint, that replacing a logical
// manifest path and then removing it from the latest revision does NOT make
// historically committed digest keys eligible for database GC. It verifies
// historical bytes via a distinct reader-only service principal.
//
// This is NOT server-enforced WORM: the SHA-pinned historical MinIO fixture
// still permits a scoped writer to overwrite keys via unconditional PUT.
// No product or test DELETE request is issued for retained objects.
func TestWorkspaceRealMinIOHistoricalRetainedBytesPG(t *testing.T) {
	endpoint := os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT")
	if endpoint == "" || os.Getenv("PGTEST_DSN") == "" {
		t.Skip("requires real IAM-provisioned MinIO and PostgreSQL16")
	}
	role := func(name string) (string, string) {
		access := os.Getenv("S3BLOB_IAM_" + name + "_ACCESS_KEY")
		secret := os.Getenv("S3BLOB_IAM_" + name + "_SECRET_KEY")
		if access == "" || secret == "" {
			t.Fatalf("missing separate non-admin %s identity", name)
		}
		return access, secret
	}
	makeStore := func(name string) *s3blob.Store {
		access, secret := role(name)
		store, err := s3blob.New(s3blob.Config{
			Endpoint:          endpoint,
			Bucket:            "research-artifacts",
			Region:            "us-east-1",
			AccessKey:         access,
			SecretKey:         secret,
			AllowHTTPForTests: true,
		})
		if err != nil {
			t.Fatalf("construct real MinIO %s role: %v", name, err)
		}
		return store
	}
	split, err := s3blob.NewSplitRoleStore(makeStore("WRITER"), makeStore("READER"))
	if err != nil {
		t.Fatal(err)
	}

	repo, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repo, 98602)
	if _, _, err := repo.OpenWorkspace(ctx, lock); err != nil {
		t.Fatalf("open pinned Workspace: %v", err)
	}

	const logicalPath = "reports/historical-minio.md"
	var historical [2]workspace.Asset
	var originals [2][]byte
	var receipts [2]WorkspaceCommitReceipt
	var inputs [2]WorkspaceCommitInput
	for idx := 0; idx < 2; idx++ {
		payload := []byte([]string{
			"P0-2B6 v1 immutable historical report on real MinIO and PostgreSQL16",
			"P0-2B6 v2 replacement report on real MinIO and PostgreSQL16",
		}[idx])
		sum := sha256.Sum256(payload)
		asset := workspace.Asset{
			Path:      logicalPath,
			Digest:    "sha256:" + hex.EncodeToString(sum[:]),
			SizeBytes: int64(len(payload)),
		}
		intent := WorkspaceUploadInput{
			IntentID:     []string{"history-upload-v1", "history-upload-v2"}[idx],
			Asset:        asset,
			LeaseSeconds: 300,
		}
		stage, err := repo.UploadWorkspaceObject(ctx, lock, intent, bytes.NewReader(payload), split)
		if err != nil || stage.Asset != asset {
			t.Fatalf("real scoped upload revision %d: stage=%+v err=%v", idx+1, stage, err)
		}
		input := WorkspaceCommitInput{
			CommitID:         []string{"history-commit-v1", "history-commit-v2"}[idx],
			ExpectedRevision: int64(idx),
			Assets:           []workspace.Asset{asset},
		}
		receipt, err := New(pool).CommitStagedWorkspace(ctx, lock, input, split)
		if err != nil || receipt.Revision != int64(idx+1) {
			t.Fatalf("real verified Manifest CAS revision %d: receipt=%+v err=%v", idx+1, receipt, err)
		}
		originals[idx], historical[idx], receipts[idx], inputs[idx] = payload, asset, receipt, input
		current, err := New(pool).ReadVerifiedWorkspaceAsset(ctx, lock, logicalPath, split)
		if err != nil || !bytes.Equal(current, payload) {
			t.Fatalf("fresh reader cannot verify current revision %d: err=%v", idx+1, err)
		}
	}
	if historical[0].Digest == historical[1].Digest {
		t.Fatal("distinct historical revisions must not alias the same digest key")
	}

	// A third metadata-only revision removes the path from the current
	// manifest. Historical v1/v2 refs and bytes must still survive.
	empty := WorkspaceCommitInput{
		CommitID:         "history-commit-empty",
		ExpectedRevision: 2,
		Assets:           nil,
	}
	third, err := New(pool).CommitStagedWorkspace(ctx, lock, empty, nil)
	if err != nil || third.Revision != 3 {
		t.Fatalf("empty revision after two verified real-byte commits: %+v err=%v", third, err)
	}
	freshRepo := New(pool)
	snapshot, currentAssets, err := freshRepo.ReadWorkspaceSnapshot(ctx, lock)
	if err != nil || snapshot.Revision != 3 || len(currentAssets) != 0 {
		t.Fatalf("latest snapshot was not empty revision 3: state=%+v assets=%+v err=%v", snapshot, currentAssets, err)
	}
	if _, err := freshRepo.ReadVerifiedWorkspaceAsset(ctx, lock, logicalPath, split); !errors.Is(err, ErrWorkspaceAssetNotFound) {
		t.Fatalf("old path incorrectly exposed as current after empty revision: %v", err)
	}
	for idx, asset := range historical {
		oldBytes, err := split.ReadAsset(ctx, lock.TenantID, lock.WorkspaceID, asset)
		if err != nil || !bytes.Equal(oldBytes, originals[idx]) {
			t.Fatalf("historical revision %d is missing or corrupted: %v", idx+1, err)
		}
		if replay, err := freshRepo.CommitStagedWorkspace(ctx, lock, inputs[idx], nil); err != nil || replay != receipts[idx] {
			t.Fatalf("immutable older revision %d receipt cannot be replayed after newer CAS: %+v err=%v", idx+1, replay, err)
		}
		if _, err := freshRepo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "history-gc-probe", 30); !errors.Is(err, ErrGCNotEligible) {
			t.Fatalf("historical revision %d digest became eligible for PG GC: %v", idx+1, err)
		}
	}
	if replay, err := freshRepo.CommitStagedWorkspace(ctx, lock, empty, nil); err != nil || replay != third {
		t.Fatalf("empty latest receipt replay changed revision 3: %+v err=%v", replay, err)
	}

	var stages, refs, commits, retained, claims int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_stages").Scan(&stages); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_commit_refs").Scan(&refs); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_manifest_commits").Scan(&commits); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_gc_observations WHERE disposition='RETAINED'").Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_gc_claims").Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if stages != 2 || refs != 2 || commits != 3 || retained != 2 || claims != 0 {
		t.Fatalf("historical retention ledger unexpected: stages=%d refs=%d commits=%d retained=%d claims=%d",
			stages, refs, commits, retained, claims)
	}
	for idx, asset := range historical {
		var matched int
		err := pool.QueryRow(ctx, `
			SELECT count(*) FROM workspace_blob_commit_refs
			WHERE tenant_id=$1 AND workspace_id=$2 AND owner_principal_id=$3
			  AND manifest_revision=$4 AND asset_path=$5 AND artifact_digest=$6 AND size_bytes=$7
		`, lock.TenantID, lock.WorkspaceID, lock.PrincipalID, int64(idx+1),
			asset.Path, asset.Digest, asset.SizeBytes).Scan(&matched)
		if err != nil || matched != 1 {
			t.Fatalf("historical revision %d lost its exact immutable reference: count=%d err=%v", idx+1, matched, err)
		}
	}
	t.Log("REAL MINIO HISTORICAL RETENTION PASS: separate IAM reader verified v1/v2 bytes after v3 empty CAS; immutable revisions and refs retained; both GC claims DENIED; no S3 DELETE")
}
