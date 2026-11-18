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

func minioRoleStore(t *testing.T, role string) *Store {
	t.Helper()
	access := os.Getenv("S3BLOB_IAM_" + role + "_ACCESS_KEY")
	secret := os.Getenv("S3BLOB_IAM_" + role + "_SECRET_KEY")
	if access == "" || secret == "" {
		t.Fatalf("missing real MinIO %s role, never substitute admin credentials", role)
	}
	// Each disposable IAM probe must use a fresh connection. A legacy
	// provider may close an idle connection after a denied request; reusing
	// it for a later positive PUT makes the result indeterminate. Do not
	// retry the write or relax provider status/byte assertions.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	t.Cleanup(transport.CloseIdleConnections)
	store, err := New(Config{
		HTTPClient: &http.Client{Transport: transport},
		Endpoint:   os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT"),
		Bucket:     "research-artifacts", Region: "us-east-1",
		AccessKey:  access, SecretKey: secret, AllowHTTPForTests: true,
	})
	if err != nil {
		t.Fatalf("create real MinIO %s role: %v", role, err)
	}
	return store
}

func realIAMStatus(t *testing.T, ctx context.Context, store *Store, method, path string, body []byte, conditional bool) int {
	t.Helper()
	request, err := store.signedRequest(ctx, method, path, body, conditional)
	if err != nil {
		t.Fatalf("prepare real role request: %v", err)
	}
	response, err := store.client.Do(request)
	if err != nil {
		t.Fatalf("send real role request: %v", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	return response.StatusCode
}

func TestMinIORealScopedIAM(t *testing.T) {
	if os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT") == "" {
		t.Skip("requires real provider IAM users and a disposable MinIO server")
	}
	ctx := context.Background()
	writer := minioRoleStore(t, "WRITER")
	reader := minioRoleStore(t, "READER")
	other := minioRoleStore(t, "OTHER")
	denied := minioRoleStore(t, "DENIED")

	split, err := NewSplitRoleStore(writer, reader)
	if err != nil {
		t.Fatalf("construct two separate service principals: %v", err)
	}
	if _, err := NewSplitRoleStore(writer, writer); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("same principal could get combined upload/read privilege: %v", err)
	}
	payload := []byte("P0-2B5b real MinIO separate writer and verified reader, not bootstrap administrator")
	sum := sha256.Sum256(payload)
	asset := workspace.Asset{
		Path:   "reports/iam-report.md",
		Digest: "sha256:" + hex.EncodeToString(sum[:]), SizeBytes: int64(len(payload)),
	}
	tenant, workspaceID := "tenant-integration", "workspace-1"
	key, err := writer.objectPath(tenant, workspaceID, asset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if status := realIAMStatus(t, ctx, writer, http.MethodPut, key, payload, true); status != http.StatusOK {
		t.Fatalf("real scoped writer could not PUT with conditional header: HTTP %d", status)
	}
	readBack, err := split.ReadAsset(ctx, tenant, workspaceID, asset)
	if err != nil || !bytes.Equal(readBack, payload) {
		t.Fatalf("real scoped reader did not hash actual bytes: %v", err)
	}
	if status := realIAMStatus(t, ctx, writer, http.MethodPut, key, payload, true); status != http.StatusPreconditionFailed {
		t.Fatalf("existing digest key was not write-once under conditional PUT: HTTP %d", status)
	}
	if _, err := split.Upload(ctx, tenant, workspaceID, asset.Path, bytes.NewReader(payload)); err != nil {
		t.Fatalf("two-role upload retry should verify real existing bytes: %v", err)
	}

	for _, tc := range []struct {
		name, method, path string
		store              *Store
		data               []byte
		conditional        bool
	}{
		{"writer-cannot-read", http.MethodGet, key, writer, nil, false},
		{"reader-cannot-put", http.MethodPut, key, reader, payload, true},
		{"reader-cannot-delete", http.MethodDelete, key, reader, nil, false},
		{"writer-cannot-delete", http.MethodDelete, key, writer, nil, false},
		{"other-tenant-cannot-read", http.MethodGet, key, other, nil, false},
		{"other-tenant-cannot-write", http.MethodPut, key, other, payload, true},
		{"unassigned-cannot-read", http.MethodGet, key, denied, nil, false},
		{"unassigned-cannot-write", http.MethodPut, key, denied, payload, true},
		{"writer-cannot-list-buckets", http.MethodGet, "/", writer, nil, false},
		{"reader-cannot-list-buckets", http.MethodGet, "/", reader, nil, false},
		{"other-tenant-cannot-list-buckets", http.MethodGet, "/", other, nil, false},
		{"unauthorized-cannot-list-buckets", http.MethodGet, "/", denied, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := realIAMStatus(t, ctx, tc.store, tc.method, tc.path, tc.data, tc.conditional)
			if status != http.StatusForbidden {
				t.Fatalf("MinIO IAM did not independently DENY: method=%s status=%d", tc.method, status)
			}
		})
	}
	// Denial must not be mistaken for a missing object by the trusted
	// byte verifier, because callers may need to retain an UNKNOWN state.
	if err := writer.VerifyAsset(ctx, tenant, workspaceID, asset); !errors.Is(err, ErrStorage) {
		t.Fatalf("unprivileged GET incorrectly treated as missing: %v", err)
	}
	bTenant, bWorkspace := "tenant-iam-b", "workspace-iam-b"
	if status := realIAMStatus(t, ctx, other, http.MethodPut,
		func() string {
			k, e := other.objectPath(bTenant, bWorkspace, asset.Digest)
			if e != nil {
				t.Fatal(e)
			}
			return k
		}(), payload, true); status != http.StatusOK {
		t.Fatalf("other tenant cannot write its OWN prefix: HTTP %d", status)
	}
	if err := other.VerifyAsset(ctx, bTenant, bWorkspace, asset); err != nil {
		t.Fatalf("other tenant cannot verify its OWN prefix: %v", err)
	}
	t.Log("real provider IAM: scoped write-only + read-only + foreign-tenant + unassigned user denials; conditional 412")
}

func TestMinIORealIAMDisabledReader(t *testing.T) {
	if os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT") == "" {
		t.Skip("requires real MinIO user disable event from approved CI fixture")
	}
	reader := minioRoleStore(t, "READER")
	tenant, workspaceID := "tenant-integration", "workspace-1"
	report := []byte("P0-2B5b real MinIO separate writer and verified reader, not bootstrap administrator")
	sum := sha256.Sum256(report)
	asset := workspace.Asset{
		Path:   "reports/iam-report.md",
		Digest: "sha256:" + hex.EncodeToString(sum[:]), SizeBytes: int64(len(report)),
	}
	ctx := context.Background()
	key, err := reader.objectPath(tenant, workspaceID, asset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	// S3 IAM revocation must affect the real object that was successfully
	// read before the user was disabled. It is never a 404/missing-object.
	status := realIAMStatus(t, ctx, reader, http.MethodGet, key, nil, false)
	if status != http.StatusForbidden {
		t.Fatalf("disabled read identity remained authorized: HTTP %d (expected 403)", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, asset); !errors.Is(err, ErrStorage) {
		t.Fatalf("revoked read authorization misclassified as missing or success: %v", err)
	}
	t.Log("real MinIO user disable enforced by provider; read denial remains ErrStorage, not ErrObjectMissing")
}
