package s3blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/workspace"
)

// TestMinIOLegacyUnconditionalOverwriteGap is intentionally NEGATIVE
// interoperability evidence. The scoped MinIO writer's s3:PutObject policy
// does not force every caller to send If-None-Match. A compliant upload
// client gets 412, but a raw SigV4 PUT without that condition can replace
// the same content-addressed key. A green result here is a SECURITY BLOCKER,
// not a write-once acceptance result and never authorizes production use.
//
// This fixture only touches a disposable CI bucket using test identities.
// It must run before the separate test revokes the reader principal.
func TestMinIOLegacyUnconditionalOverwriteGap(t *testing.T) {
	if os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT") == "" {
		t.Skip("requires disposable real legacy MinIO and scoped IAM identities")
	}
	ctx := context.Background()
	writer := minioRoleStore(t, "WRITER")
	reader := minioRoleStore(t, "READER")
	const tenant, workspaceID = "tenant-integration", "workspace-1"

	original := []byte("P0-2B5c: legacy provider conditional write is client-controlled, not server-mandated")
	sum := sha256.Sum256(original)
	asset := workspace.Asset{
		Path:      "reports/legacy-write-once-gap.md",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		SizeBytes: int64(len(original)),
	}
	key, err := writer.objectPath(tenant, workspaceID, asset.Digest)
	if err != nil {
		t.Fatal(err)
	}

	if status := realIAMStatus(t, ctx, writer, http.MethodPut, key, original, true); status != http.StatusOK {
		t.Fatalf("initial scoped conditional PUT rejected HTTP %d", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, asset); err != nil {
		t.Fatalf("initial real scoped byte verification failed: %v", err)
	}
	if status := realIAMStatus(t, ctx, writer, http.MethodPut, key, original, true); status != http.StatusPreconditionFailed {
		t.Fatalf("compliant duplicate conditional PUT was not 412: HTTP %d", status)
	}

	malicious := bytes.Clone(original)
	malicious[0] ^= 0x01
	// Same digest-derived KEY but different BYTES. This raw signed request
	// deliberately BYPASSES the ACP conditional-put method. It is not a new
	// product capability, and it runs only on the temporary CI MinIO server.
	if status := realIAMStatus(t, ctx, writer, http.MethodPut, key, malicious, false); status != http.StatusOK {
		t.Fatalf("legacy provider behavior changed: unconditional PUT now HTTP %d (re-evaluate policy and security gate)", status)
	}
	// The independent, read-only principal must detect corruption even
	// when both the object key and payload SIZE are unchanged.
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, asset); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("post-overwrite verified reader did not reject malicious bytes: %v", err)
	}
	request, err := reader.signedRequest(ctx, http.MethodGet, key, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	response, err := reader.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("raw scoped reader GET failed HTTP %d", response.StatusCode)
	}
	actual, err := io.ReadAll(io.LimitReader(response.Body, MaxUploadBytes+1))
	if err != nil || !bytes.Equal(actual, malicious) {
		t.Fatalf("no proof of same-key byte replacement: response bytes=%d err=%v", len(actual), err)
	}
	t.Log("EXPECTED SECURITY BLOCKER: legacy scoped writer bypassed If-None-Match with unconditional PUT (HTTP 200); independent reader rejected modified bytes as ErrIntegrity; provider WORM NOT proven")
}
