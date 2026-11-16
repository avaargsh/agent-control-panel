package s3blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The COPY security probe must use independent SigV4 signing. A 403 from a
// request whose copy-source header is not signed is NOT provider policy proof.
func TestIndependentRawSigV4CopySourceIsSigned(t *testing.T) {
	identity, err := New(Config{
		Endpoint: "https://s3.us-east-1.amazonaws.com",
		Bucket: "acp-writeonce-probe-fixture",
		Region: "us-east-1",
		AccessKey: "scoped-copy-probe",
		SecretKey: "scoped-copy-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("copy-source-canary")
	digest := sha256.Sum256(payload)
	source := "/acp-writeonce-probe-fixture/v1/tenant/tenant-security-probe/workspace/workspace-writeonce-probe/sha256/" + hex.EncodeToString(digest[:])
	destination := "/acp-writeonce-probe-fixture/validation/copy-positive-control"
	req, err := rawS3SignedCopyRequest(context.Background(), identity, destination, source)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodPut || req.URL.EscapedPath() != destination {
		t.Fatal("COPY signer changed HTTP method or destination")
	}
	if got := req.Header.Get("X-Amz-Copy-Source"); got != source {
		t.Fatalf("COPY source not preserved: %q", got)
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "SignedHeaders=host;x-amz-content-sha256;x-amz-copy-source;x-amz-date,") {
		t.Fatalf("COPY source missing from signed headers: %q", auth)
	}
	empty := sha256.Sum256(nil)
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != hex.EncodeToString(empty[:]) {
		t.Fatal("COPY request must sign its empty request payload")
	}
	if req.Header.Get("If-None-Match") != "" {
		t.Fatal("security bypass probe must not silently add If-None-Match")
	}
}

// rawS3CopyStatus observes a REAL signed CopyObject request, including the
// returned XML. S3 may return HTTP 200 with an embedded XML Error; callers
// must not count that as a successful positive authorization control.
func rawS3CopyStatus(t *testing.T, ctx context.Context, identity *Store, destination, source string) (int, string) {
	t.Helper()
	req, err := rawS3SignedCopyRequest(ctx, identity, destination, source)
	if err != nil {
		t.Fatalf("build independently signed CopyObject: %v", err)
	}
	resp, err := identity.client.Do(req)
	if err != nil {
		t.Fatalf("execute independently signed CopyObject: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		t.Fatalf("read CopyObject response: %v", err)
	}
	return resp.StatusCode, string(body)
}

// A positive CopyObject response is meaningful only when an independent GET
// confirms that the copied bytes actually landed at the unprotected canary.
func rawS3ReadCopyCanary(t *testing.T, ctx context.Context, identity *Store, path string) []byte {
	t.Helper()
	req, err := rawS3SignedRequest(ctx, identity, http.MethodGet, path, nil, false)
	if err != nil {
		t.Fatalf("sign copy-positive control GET: %v", err)
	}
	resp, err := identity.client.Do(req)
	if err != nil {
		t.Fatalf("copy-positive control GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("copy-positive control GET was denied: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		t.Fatalf("read copy-positive control bytes: %v", err)
	}
	return body
}

func TestIndependentRawSigV4CopyRequestRejectsUnsafeSource(t *testing.T) {
	identity, err := New(Config{
		Endpoint: "https://s3.us-east-1.amazonaws.com",
		Bucket: "acp-writeonce-probe-fixture",
		Region: "us-east-1",
		AccessKey: "scoped-copy-probe",
		SecretKey: "scoped-copy-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"bucket/key", "/bucket/key?versionId=secret", "/bucket/key\\r\\nX-Amz-Evil: true"} {
		if _, err := rawS3SignedCopyRequest(context.Background(), identity, "/bucket/destination", source); err == nil {
			t.Fatalf("unsafe copy source was accepted: %q", source)
		}
	}
}

func TestIndependentRawSigV4CopyHasNoAccidentalPayload(t *testing.T) {
	identity, err := New(Config{
		Endpoint: "https://s3.us-east-1.amazonaws.com",
		Bucket: "acp-writeonce-probe-fixture",
		Region: "us-east-1",
		AccessKey: "scoped-copy-probe",
		SecretKey: "scoped-copy-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := rawS3SignedCopyRequest(context.Background(), identity, "/bucket/target", "/bucket/source")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil || !bytes.Equal(body, []byte{}) {
		t.Fatal("COPY signed request must have a zero-length body")
	}
}
