package s3blob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestMinIOBackend is skipped during the default unit suite. A dedicated
// workflow injects a real disposable MinIO endpoint and executes it. The
// in-process HTTP fake in store_test.go is NOT a replacement for this test.
func TestMinIOBackend(t *testing.T) {
	endpoint := os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("S3BLOB_MINIO_TEST_ENDPOINT not provided")
	}
	access := os.Getenv("S3BLOB_MINIO_TEST_ACCESS_KEY")
	secret := os.Getenv("S3BLOB_MINIO_TEST_SECRET_KEY")
	if access == "" || secret == "" {
		t.Fatal("MinIO integration credentials missing")
	}
	store, err := New(Config{
		Endpoint: endpoint, Bucket: "research-artifacts", Region: "us-east-1",
		AccessKey: access, SecretKey: secret, AllowHTTPForTests: true,
	})
	if err != nil {
		t.Fatalf("initialize MinIO adapter: %v", err)
	}
	ctx := context.Background()

	// Bootstrapping a fresh throwaway test bucket is test-only, never part of
	// the production adapter's Workspace API.
	request, err := store.signedRequest(ctx, http.MethodPut, "/research-artifacts", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	response, err := store.client.Do(request)
	if err != nil {
		t.Fatalf("create test bucket: %v", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		t.Fatalf("create test bucket HTTP %d", response.StatusCode)
	}

	report := []byte("P0-2B actual MinIO bytes, not just a metadata receipt")
	asset, err := store.Upload(ctx, "tenant-acceptance", "workspace-1", "reports/research.md", bytes.NewReader(report))
	if err != nil {
		t.Fatalf("MinIO PutObject+GetObject verify: %v", err)
	}
	actual, err := store.ReadAsset(ctx, "tenant-acceptance", "workspace-1", asset)
	if err != nil || !bytes.Equal(actual, report) {
		t.Fatalf("MinIO raw object read mismatch: %v", err)
	}
	if _, err := store.Upload(ctx, "tenant-acceptance", "workspace-1", asset.Path, bytes.NewReader(report)); err != nil {
		t.Fatalf("MinIO conditional duplicate PutObject: %v", err)
	}
	if err := store.VerifyAsset(ctx, "tenant-other", "workspace-1", asset); !errors.Is(err, ErrObjectMissing) {
		t.Fatalf("MinIO cross-tenant object read was not isolated: %v", err)
	}
	key, err := store.objectPath("tenant-acceptance", "workspace-1", asset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	// A privileged external overwrite (outside this adapter) is simulated
	// deliberately: the read path must hash actual object bytes and reject it.
	bad := []byte(strings.Repeat("x", len(report)))
	overwrite, err := store.signedRequest(ctx, http.MethodPut, key, bad, false)
	if err != nil {
		t.Fatal(err)
	}
	overwritten, err := store.client.Do(overwrite)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(overwritten.Body, 4096))
	_ = overwritten.Body.Close()
	if overwritten.StatusCode != http.StatusOK {
		t.Fatalf("privileged MinIO tamper fixture HTTP %d", overwritten.StatusCode)
	}
	if _, err := store.ReadAsset(ctx, "tenant-acceptance", "workspace-1", asset); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("MinIO tampered payload accepted: %v", err)
	}
	removed, err := store.signedRequest(ctx, http.MethodDelete, key, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := store.client.Do(removed)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(deleted.Body, 4096))
	_ = deleted.Body.Close()
	if deleted.StatusCode != http.StatusNoContent && deleted.StatusCode != http.StatusOK {
		t.Fatalf("delete MinIO fixture HTTP %d", deleted.StatusCode)
	}
	if err := store.VerifyAsset(ctx, "tenant-acceptance", "workspace-1", asset); !errors.Is(err, ErrObjectMissing) {
		t.Fatalf("deleted MinIO payload accepted: %v", err)
	}
}
