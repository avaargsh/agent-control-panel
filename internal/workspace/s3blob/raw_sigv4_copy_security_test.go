package s3blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
