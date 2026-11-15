package s3blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/workspace"
)

// TestApprovedS3WriteOnceSecurityGate is a SEPARATE fail-closed provider
// promotion gate. It is never satisfied by the legacy MinIO gap test.
// An operator must explicitly provision a disposable HTTPS bucket with
// server-enforced conditional writes and distinct least-privilege principals.
// This test intentionally leaves canary objects in that scratch bucket,
// which must not hold real tenant data. No DELETE method is introduced.
func TestApprovedS3WriteOnceSecurityGate(t *testing.T) {
	if os.Getenv("S3BLOB_WORM_GATE_APPROVAL") == "" {
		t.Skip("blocked: requires separately approved, protected disposable HTTPS S3 provider acceptance")
	}
	if os.Getenv("S3BLOB_WORM_GATE_APPROVAL") != "approved-disposable-provider" {
		t.Fatal("unrecognized S3 write-once acceptance approval")
	}
	endpoint := os.Getenv("S3BLOB_WORM_ENDPOINT")
	bucket := os.Getenv("S3BLOB_WORM_BUCKET")
	if !strings.HasPrefix(endpoint, "https://") ||
		!strings.HasPrefix(bucket, "acp-writeonce-probe-") {
		t.Fatal("refuse non-HTTPS endpoint or non-disposable probe bucket")
	}
	access := os.Getenv("S3BLOB_WORM_WRITER_ACCESS_KEY")
	secret := os.Getenv("S3BLOB_WORM_WRITER_SECRET_KEY")
	readAccess := os.Getenv("S3BLOB_WORM_READER_ACCESS_KEY")
	readSecret := os.Getenv("S3BLOB_WORM_READER_SECRET_KEY")
	if access == "" || secret == "" || readAccess == "" || readSecret == "" || access == readAccess {
		t.Fatal("require separately provisioned, distinct approved writer-only and reader-only principals")
	}
	writer, err := New(Config{Endpoint: endpoint, Bucket: bucket, Region: "us-east-1", AccessKey: access, SecretKey: secret})
	if err != nil {
		t.Fatalf("approved writer config: %v", err)
	}
	reader, err := New(Config{Endpoint: endpoint, Bucket: bucket, Region: "us-east-1", AccessKey: readAccess, SecretKey: readSecret})
	if err != nil {
		t.Fatalf("approved reader config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	original := []byte(fmt.Sprintf("P0-2B5c approved HTTPS provider unconditional-write protection canary=%x", nonce))
	sum := sha256.Sum256(original)
	asset := workspace.Asset{
		Path: "reports/approved-writeonce-gate.md",
		Digest: "sha256:" + hex.EncodeToString(sum[:]),
		SizeBytes: int64(len(original)),
	}
	const tenant, workspaceID = "tenant-security-probe", "workspace-writeonce-probe"
	key, err := writer.objectPath(tenant, workspaceID, asset.Digest)
	if err != nil {
		t.Fatal(err)
	}

	if status := realIAMStatus(t, ctx, writer, http.MethodPut, key, original, true); status != http.StatusOK {
		t.Fatalf("approved provider rejected initial conditional PUT: HTTP %d", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, asset); err != nil {
		t.Fatalf("approved provider did not return correct initial bytes: %v", err)
	}
	if status := realIAMStatus(t, ctx, writer, http.MethodPut, key, original, true); status != http.StatusPreconditionFailed {
		t.Fatalf("approved provider must reject existing-key conditional PUT as 412, got %d", status)
	}

	different := bytes.Clone(original)
	different[0] ^= 0x01
	// Send one raw *signed* S3 PUT WITHOUT If-None-Match, deliberately
	// bypassing every ACP convenience upload method. Only the backend IAM
	// policy can block this attempt. A 200 here is an immediate hard FAIL.
	if status := realIAMStatus(t, ctx, writer, http.MethodPut, key, different, false); status != http.StatusForbidden {
		t.Fatalf("P0 WRITE-ONCE FAILURE: valid scoped writer unconditionally re-PUT same key (status=%d, want provider 403)", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, asset); err != nil {
		t.Fatalf("write-once denial did not preserve immutable original bytes: %v", err)
	}
	if status := realIAMStatus(t, ctx, writer, http.MethodDelete, key, nil, false); status != http.StatusForbidden {
		t.Fatalf("scoped writer could DELETE object despite WORM acceptance: HTTP %d", status)
	}
	if status := realIAMStatus(t, ctx, reader, http.MethodPut, key, different, false); status != http.StatusForbidden {
		t.Fatalf("read-only identity could overwrite object: HTTP %d", status)
	}
	foreignKey, err := writer.objectPath("tenant-other-probe", workspaceID, asset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if status := realIAMStatus(t, ctx, writer, http.MethodPut, foreignKey, original, true); status != http.StatusForbidden {
		t.Fatalf("scoped writer could cross tenant boundary: HTTP %d", status)
	}
	// Even if a future object-store implementation reports an error for
	// 403, it must remain distinguishable from a missing object.
	if err := writer.VerifyAsset(ctx, tenant, workspaceID, asset); !errors.Is(err, ErrStorage) {
		t.Fatalf("write-only principal GET denial must be ErrStorage, got %v", err)
	}
	t.Log("APPROVED S3 WORM CONTRACT PASS: provider 403 for raw unconditional PUT, 412 for duplicate conditional PUT; original bytes preserved; DELETE and tenant escape denied")
}
