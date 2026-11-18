package s3blob

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestMinIORoleProbeDoesNotReuseConnections(t *testing.T) {
	var mu sync.Mutex
	seen := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		seen[req.RemoteAddr]++
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	t.Setenv("S3BLOB_MINIO_TEST_ENDPOINT", server.URL)
	t.Setenv("S3BLOB_IAM_WRITER_ACCESS_KEY", "fixture-writer")
	t.Setenv("S3BLOB_IAM_WRITER_SECRET_KEY", "fixture-secret-writer")
	t.Setenv("S3BLOB_IAM_READER_ACCESS_KEY", "fixture-reader")
	t.Setenv("S3BLOB_IAM_READER_SECRET_KEY", "fixture-secret-reader")
	writer := minioRoleStore(t, "WRITER")
	reader := minioRoleStore(t, "READER")
	const path = "/research-artifacts/v1/tenant/test/workspace/test/sha256/probe"
	for _, store := range []*Store{writer, reader, writer, reader} {
		if got := realIAMStatus(t, context.Background(), store, http.MethodPut, path, []byte("probe"), true); got != http.StatusForbidden {
			t.Fatalf("unexpected HTTP status %d", got)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 4 {
		t.Fatalf("IAM probes reused connections across requests or roles: %v", seen)
	}
}
