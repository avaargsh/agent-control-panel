package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/workspace/s3blob"
)

func TestWorkspaceSignedS3BlobRecoveryAndCorruption(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repo, 97900)
	if _, _, err := repo.OpenWorkspace(ctx, lock); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	objects := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/research-artifacts/v1/tenant/") ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			http.Error(w, "bad scope/signature", http.StatusForbidden)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("If-None-Match") != "*" {
				http.Error(w, "no write once", http.StatusPreconditionRequired)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, s3blob.MaxUploadBytes+1))
			sum := sha256.Sum256(body)
			if err != nil || hex.EncodeToString(sum[:]) != r.Header.Get("X-Amz-Content-Sha256") {
				http.Error(w, "bad payload", http.StatusBadRequest)
				return
			}
			if _, exists := objects[r.URL.Path]; exists {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			objects[r.URL.Path] = body
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body, exists := objects[r.URL.Path]
			if !exists {
				http.Error(w, "missing", http.StatusNotFound)
				return
			}
			_, _ = w.Write(body)
		default:
			http.Error(w, "not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	store, err := s3blob.New(s3blob.Config{
		Endpoint: srv.URL, Bucket: "research-artifacts", Region: "us-east-1",
		AccessKey: "test-access", SecretKey: "test-secret", AllowHTTPForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	report := []byte("Research report with signed object-store persistence")
	asset, err := store.Upload(ctx, lock.TenantID, lock.WorkspaceID,
		"reports/research.md", bytes.NewReader(report))
	if err != nil {
		t.Fatalf("upload raw bytes: %v", err)
	}
	receipt, err := repo.CommitWorkspace(ctx, lock, WorkspaceCommitInput{
		CommitID: "commit-http-report", ExpectedRevision: 0, Assets: []workspace.Asset{asset},
	}, store)
	if err != nil || receipt.Revision != 1 {
		t.Fatalf("commit verified object: %+v err=%v", receipt, err)
	}
	// Reopen in a fresh Repository and re-download the bytes through a scoped
	// signed S3 GET, not the manifest's JSON digest alone.
	actual, err := New(pool).ReadVerifiedWorkspaceAsset(ctx, lock, asset.Path, store)
	if err != nil || !bytes.Equal(actual, report) {
		t.Fatalf("reopen/verify report bytes: %q err=%v", actual, err)
	}
	foreign := lock
	foreign.TenantID = "tenant-other"
	if _, err := New(pool).ReadVerifiedWorkspaceAsset(ctx, foreign, asset.Path, store); !errors.Is(err, ErrWorkspaceScope) {
		t.Fatalf("foreign Workspace read permitted: %v", err)
	}
	if _, err := New(pool).ReadVerifiedWorkspaceAsset(ctx, lock, "reports/not-in-manifest.md", store); !errors.Is(err, ErrWorkspaceAssetNotFound) {
		t.Fatalf("uncommitted object read permitted: %v", err)
	}
	// Corrupt bytes in the *same* object key after commit. A metadata-only
	// reader would miss the problem; the verified reader must fail closed.
	mu.Lock()
	for key := range objects {
		objects[key] = bytes.Repeat([]byte("X"), len(report))
	}
	mu.Unlock()
	if _, err := New(pool).ReadVerifiedWorkspaceAsset(ctx, lock, asset.Path, store); !errors.Is(err, s3blob.ErrIntegrity) {
		t.Fatalf("tampered object accepted: %v", err)
	}
	mu.Lock()
	for key := range objects {
		delete(objects, key)
	}
	mu.Unlock()
	if _, err := New(pool).ReadVerifiedWorkspaceAsset(ctx, lock, asset.Path, store); !errors.Is(err, s3blob.ErrObjectMissing) {
		t.Fatalf("deleted blob accepted: %v", err)
	}
}
