package s3blob

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

	"github.com/avaargsh/agent-control-panel/internal/workspace"
)

type wireStore struct {
	mu sync.Mutex
	objects map[string][]byte
	signatures int
}

func fakeS3(t *testing.T) (*Store, *wireStore, *httptest.Server) {
	t.Helper()
	fake := &wireStore{objects: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/research-artifacts/v1/tenant/") {
			http.Error(w, "wrong bucket or namespace", http.StatusBadRequest)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=test-access/") ||
			!strings.Contains(auth, "SignedHeaders=") || !strings.Contains(auth, "Signature=") ||
			r.Header.Get("X-Amz-Date") == "" || r.Header.Get("X-Amz-Content-Sha256") == "" {
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		fake.mu.Lock()
		fake.signatures++
		defer fake.mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("If-None-Match") != "*" {
				http.Error(w, "conditional write required", http.StatusPreconditionRequired)
				return
			}
			b, err := io.ReadAll(io.LimitReader(r.Body, MaxUploadBytes+1))
			if err != nil || int64(len(b)) > MaxUploadBytes {
				http.Error(w, "bad upload", http.StatusBadRequest)
				return
			}
			digest := sha256.Sum256(b)
			if r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(digest[:]) {
				http.Error(w, "bad signed payload", http.StatusForbidden)
				return
			}
			if _, ok := fake.objects[r.URL.Path]; ok {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			fake.objects[r.URL.Path] = bytes.Clone(b)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			b, ok := fake.objects[r.URL.Path]
			if !ok {
				http.Error(w, "missing", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
		default:
			http.Error(w, "unsupported", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(srv.Close)
	store, err := New(Config{
		Endpoint: srv.URL, Region: "us-east-1", Bucket: "research-artifacts",
		AccessKey: "test-access", SecretKey: "test-secret", AllowHTTPForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, fake, srv
}

func TestUploadReadVerifyBytesAndIdempotentPut(t *testing.T) {
	store, fake, _ := fakeS3(t)
	ctx := context.Background()
	data := []byte("durable workspace report\nquarter: 2026Q4\n")
	asset, err := store.Upload(ctx, "tenant-a", "workspace-a", "reports/valuation.md", bytes.NewReader(data))
	if err != nil || asset.Path != "reports/valuation.md" || asset.SizeBytes != int64(len(data)) {
		t.Fatalf("upload result: %+v err=%v", asset, err)
	}
	if err := store.VerifyAsset(ctx, "tenant-a", "workspace-a", asset); err != nil {
		t.Fatalf("bytes did not verify: %v", err)
	}
	got, err := store.ReadAsset(ctx, "tenant-a", "workspace-a", asset)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read bytes: %q err=%v", got, err)
	}
	second, err := store.Upload(ctx, "tenant-a", "workspace-a", asset.Path, bytes.NewReader(data))
	if err != nil || second != asset {
		t.Fatalf("duplicate immutable PUT: %+v err=%v", second, err)
	}
	if err := store.VerifyAsset(ctx, "tenant-b", "workspace-a", asset); !errors.Is(err, ErrObjectMissing) {
		t.Fatalf("foreign tenant could access bytes: %v", err)
	}
	if err := store.VerifyAsset(ctx, "tenant-a", "workspace-b", asset); !errors.Is(err, ErrObjectMissing) {
		t.Fatalf("foreign workspace could access bytes: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.objects) != 1 || fake.signatures < 5 {
		t.Fatalf("unexpected actual signed request/byte count: %d objects %d signed calls", len(fake.objects), fake.signatures)
	}
}

func TestObjectCorruptionAndDeletionFailClosed(t *testing.T) {
	store, fake, _ := fakeS3(t)
	ctx := context.Background()
	asset, err := store.Upload(ctx, "tenant-a", "workspace-a", "reports/a.md", strings.NewReader("correct"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := store.objectPath("tenant-a", "workspace-a", asset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.objects[key] = []byte("changed")
	fake.mu.Unlock()
	if err := store.VerifyAsset(ctx, "tenant-a", "workspace-a", asset); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("same-size corruption accepted: %v", err)
	}
	if _, err := store.Upload(ctx, "tenant-a", "workspace-a", asset.Path, strings.NewReader("correct")); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("412 conflict without byte verification accepted: %v", err)
	}
	fake.mu.Lock()
	delete(fake.objects, key)
	fake.mu.Unlock()
	if _, err := store.ReadAsset(ctx, "tenant-a", "workspace-a", asset); !errors.Is(err, ErrObjectMissing) {
		t.Fatalf("missing object accepted: %v", err)
	}
}

func TestRejectsUntrustedPathScopeAndOversizedUpload(t *testing.T) {
	store, _, _ := fakeS3(t)
	for _, tc := range []struct{ tenant, ws, path string }{
		{"../tenant", "ws-1", "a.txt"},
		{"tenant-a", "../ws", "a.txt"},
		{"tenant-a", "ws-1", "../secrets"},
		{"tenant-a", "ws-1", "/root"},
	} {
		if _, err := store.Upload(context.Background(), tc.tenant, tc.ws, tc.path, strings.NewReader("x")); !errors.Is(err, ErrInvalidObject) {
			t.Fatalf("unsafe input accepted: %+v err=%v", tc, err)
		}
	}
	tooBig := bytes.NewReader(bytes.Repeat([]byte("x"), int(MaxUploadBytes+1)))
	if _, err := store.Upload(context.Background(), "tenant-a", "ws-1", "huge.txt", tooBig); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("oversized stream accepted: %v", err)
	}
	asset := workspace.Asset{Path: "a.txt", SizeBytes: -1, Digest: "sha256:" + strings.Repeat("a", 64)}
	if err := store.VerifyAsset(context.Background(), "tenant-a", "ws-1", asset); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("invalid manifest accepted: %v", err)
	}
}

func TestEndpointPoliciesAndRedirectFailClosed(t *testing.T) {
	for _, url := range []string{"http://remote.example:9000", "https://a.example/path", "https://user:pass@a.example", "https://a.example/?q=x"} {
		_, err := New(Config{Endpoint: url, Region: "us-east-1", Bucket: "research-artifacts",
			AccessKey: "test", SecretKey: "secret"})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("invalid S3 endpoint allowed: %s err=%v", url, err)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.org/stolen")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	store, err := New(Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "research-artifacts",
		AccessKey: "test", SecretKey: "secret", AllowHTTPForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upload(context.Background(), "tenant-a", "ws-1", "a.txt", strings.NewReader("x")); !errors.Is(err, ErrStorage) {
		t.Fatalf("redirect followed or accepted: %v", err)
	}
}
