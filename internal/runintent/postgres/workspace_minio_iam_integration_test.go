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

// TestWorkspaceRealMinIOScopedIAMPG is opt-in: a writer principal has only
// PutObject, a distinct reader principal only GetObject. Neither is MinIO
// admin. The separate verified-read principal confirms real bytes before
// any ACP v7 Stage and v6 Manifest CAS transaction.
func TestWorkspaceRealMinIOScopedIAMPG(t *testing.T) {
	endpoint := os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires real MinIO with independently provisioned IAM principals")
	}
	key := func(role, suffix string) string {
		value := os.Getenv("S3BLOB_IAM_" + role + "_" + suffix)
		if value == "" {
			t.Fatalf("missing MinIO role %s, cannot replace with fixture bootstrap credentials", role)
		}
		return value
	}
	makeStore := func(role string) *s3blob.Store {
		store, err := s3blob.New(s3blob.Config{
			Endpoint: endpoint, Bucket: "research-artifacts", Region: "us-east-1",
			AccessKey: key(role, "ACCESS_KEY"), SecretKey: key(role, "SECRET_KEY"),
			AllowHTTPForTests: true,
		})
		if err != nil {
			t.Fatalf("build %s principal: %v", role, err)
		}
		return store
	}
	writer, reader := makeStore("WRITER"), makeStore("READER")
	split, err := s3blob.NewSplitRoleStore(writer, reader)
	if err != nil {
		t.Fatal(err)
	}
	repo, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repo, 98601)
	if _, _, err := repo.OpenWorkspace(ctx, lock); err != nil {
		t.Fatal(err)
	}
	report := []byte("P0-2B5b committed Workspace report: writer-only PUT + reader-only GET with real server IAM")
	sum := sha256.Sum256(report)
	asset := workspace.Asset{
		Path: "reports/iam-real.md", Digest: "sha256:" + hex.EncodeToString(sum[:]),
		SizeBytes: int64(len(report)),
	}
	intent := WorkspaceUploadInput{IntentID: "iam-scoped-upload", Asset: asset, LeaseSeconds: 300}
	stage, err := repo.UploadWorkspaceObject(ctx, lock, intent, bytes.NewReader(report), split)
	if err != nil || stage.Asset != asset {
		t.Fatalf("ACP upload+reconcile with TWO real scoped principals: %+v %v", stage, err)
	}
	input := WorkspaceCommitInput{
		CommitID: "iam-scoped-commit", ExpectedRevision: 0,
		Assets: []workspace.Asset{asset},
	}
	receipt, err := repo.CommitStagedWorkspace(ctx, lock, input, split)
	if err != nil || receipt.Revision != 1 {
		t.Fatalf("IAM-scoped real byte-verified CAS: %+v %v", receipt, err)
	}
	data, err := New(pool).ReadVerifiedWorkspaceAsset(ctx, lock, asset.Path, split)
	if err != nil || !bytes.Equal(report, data) {
		t.Fatalf("PG receipt replay did not reopen via standalone read-only service principal: %v", err)
	}
	if again, err := New(pool).UploadWorkspaceObject(ctx, lock, intent, bytes.NewReader(report), split); err != nil || again != stage {
		t.Fatalf("duplicate intent MUST reconcile with reader, not blind PUT: %+v %v", again, err)
	}
	if replay, err := New(pool).CommitStagedWorkspace(ctx, lock, input, nil); err != nil || replay != receipt {
		t.Fatalf("lost-commit-ACK did not replay immutable receipt: %+v %v", replay, err)
	}
	foreign := lock
	foreign.TenantID = "tenant-iam-b"
	if _, err := New(pool).ReadVerifiedWorkspaceAsset(ctx, foreign, asset.Path, split); !errors.Is(err, ErrWorkspaceScope) {
		t.Fatalf("ACP accepted foreign tenant despite provider IAM: %v", err)
	}
	var refs int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_commit_refs").Scan(&refs); err != nil || refs != 1 {
		t.Fatalf("true IAM-split verified report missing exact retention reference: count=%d err=%v", refs, err)
	}
}
