package s3blob

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

// rawS3SignedRequest is an INDEPENDENT TEST-ONLY SigV4 HTTP request builder.
// Never delegate to Store.signedRequest, the ACP Upload path, or its HMAC /
// digest helpers: sharing the production signer would let a malformed request
// return provider 403 and be misread as successful WORM enforcement.
//
// These requests still use intentionally scoped fixture credentials. They
// have no product entry point, policy mutation, or automatic object deletion.
func rawS3SignedRequest(ctx context.Context, identity *Store, method, path string, payload []byte, ifNoneMatch bool) (*http.Request, error) {
	if identity == nil || identity.endpoint == nil || identity.accessKey == "" || identity.secretKey == "" {
		return nil, errors.New("raw SigV4 requires real scoped credentials")
	}
	endpoint := *identity.endpoint
	endpoint.Path = path
	endpoint.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	date := time.Now().UTC().Format("20060102T150405Z")
	day := date[:8]
	sha := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(sha[:])
	request.Header.Set("X-Amz-Date", date)
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)
	canonicalHeaders := map[string]string{
		"host":                 request.URL.Host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           date,
	}
	if ifNoneMatch {
		request.Header.Set("If-None-Match", "*")
		canonicalHeaders["if-none-match"] = "*"
	}
	if identity.session != "" {
		request.Header.Set("X-Amz-Security-Token", identity.session)
		canonicalHeaders["x-amz-security-token"] = identity.session
	}
	names := make([]string, 0, len(canonicalHeaders))
	for k := range canonicalHeaders {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name)
		canonical.WriteByte(':')
		canonical.WriteString(strings.TrimSpace(canonicalHeaders[name]))
		canonical.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")
	canonicalRequest := strings.Join([]string{
		method,
		request.URL.EscapedPath(),
		"", // This test signer intentionally supports no query parameters.
		canonical.String(),
		signedHeaders,
		payloadHash,
	}, "\n")
	canonicalDigest := sha256.Sum256([]byte(canonicalRequest))
	scope := day + "/" + identity.region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		date,
		scope,
		hex.EncodeToString(canonicalDigest[:]),
	}, "\n")
	// Distinct implementation from the production signHMAC function.
	hmacSHA256 := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		_, _ = h.Write([]byte(msg))
		return h.Sum(nil)
	}
	key := hmacSHA256([]byte("AWS4"+identity.secretKey), day)
	key = hmacSHA256(key, identity.region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+identity.accessKey+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+signature)
	return request, nil
}

// rawS3Status sends a test-only independently signed request to the REAL
// provider and consumes a bounded response. A status code does not constitute
// proof of a particular IAM decision until the same signer passes an allowed
// positive-control PUT with the same scoped identity.
func rawS3Status(t *testing.T, ctx context.Context, identity *Store, method, path string, payload []byte, conditional bool) int {
	t.Helper()
	request, err := rawS3SignedRequest(ctx, identity, method, path, payload, conditional)
	if err != nil {
		t.Fatalf("build independent raw SigV4 request: %v", err)
	}
	response, err := identity.client.Do(request)
	if err != nil {
		t.Fatalf("send independent raw SigV4 request: %v", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	return response.StatusCode
}

func TestIndependentRawSigV4BindsConditionalHeaderAndPayload(t *testing.T) {
	identity, err := New(Config{
		Endpoint:  "https://s3.us-east-1.amazonaws.com",
		Bucket:    "acp-writeonce-probe-fixture",
		Region:    "us-east-1",
		AccessKey: "scoped-test-id",
		SecretKey: "scoped-test-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/acp-writeonce-probe-fixture/v1/tenant/tenant-security-probe/workspace/workspace-writeonce-probe/sha256/0123456789abcdef"
	payload := []byte("raw independently signed canary")
	for _, conditional := range []bool{false, true} {
		req, err := rawS3SignedRequest(context.Background(), identity, http.MethodPut, path, payload, conditional)
		if err != nil {
			t.Fatal(err)
		}
		expectedHeader := "host;x-amz-content-sha256;x-amz-date"
		if conditional {
			expectedHeader = "host;if-none-match;x-amz-content-sha256;x-amz-date"
		}
		if !strings.Contains(req.Header.Get("Authorization"), "SignedHeaders="+expectedHeader+",") {
			t.Fatalf("unexpected signed headers (conditional=%v)", conditional)
		}
		if got := req.Header.Get("If-None-Match"); (got == "*") != conditional {
			t.Fatalf("raw header presence disagrees with signed header: %q conditional=%v", got, conditional)
		}
		sum := sha256.Sum256(payload)
		if req.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) {
			t.Fatal("payload digest is not signed independently")
		}
		if req.URL.EscapedPath() != path {
			t.Fatal("independent SigV4 signer changed destination path")
		}
		// A valid AWS4 signature is encoded into an actual request, not a
		// mock provider status that could falsely satisfy the WORM gate.
		if !strings.Contains(req.Header.Get("Authorization"), "Signature=") {
			t.Fatal("signature absent")
		}
	}
}
