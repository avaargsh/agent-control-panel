package s3blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	region := os.Getenv("S3BLOB_WORM_REGION")
	if !strings.HasPrefix(endpoint, "https://") ||
		!strings.HasPrefix(bucket, "acp-writeonce-probe-") || !validRegion(region) {
		t.Fatal("refuse non-HTTPS endpoint or non-disposable probe bucket")
	}
	access := os.Getenv("S3BLOB_WORM_WRITER_ACCESS_KEY")
	secret := os.Getenv("S3BLOB_WORM_WRITER_SECRET_KEY")
	readAccess := os.Getenv("S3BLOB_WORM_READER_ACCESS_KEY")
	readSecret := os.Getenv("S3BLOB_WORM_READER_SECRET_KEY")
	copyAccess := os.Getenv("S3BLOB_WORM_COPY_ACCESS_KEY")
	copySecret := os.Getenv("S3BLOB_WORM_COPY_SECRET_KEY")
	if access == "" || secret == "" || readAccess == "" || readSecret == "" ||
		copyAccess == "" || copySecret == "" ||
		access == readAccess || copyAccess == access || copyAccess == readAccess {
		t.Fatal("require three distinct disposable writer, reader and independently copy-capable principals")
	}
	writer, err := New(Config{Endpoint: endpoint, Bucket: bucket, Region: region, AccessKey: access, SecretKey: secret})
	if err != nil {
		t.Fatalf("approved writer config: %v", err)
	}
	reader, err := New(Config{Endpoint: endpoint, Bucket: bucket, Region: region, AccessKey: readAccess, SecretKey: readSecret})
	if err != nil {
		t.Fatalf("approved reader config: %v", err)
	}
	// The COPY principal MUST be allowed to GET an existing test source,
	// conditionally PUT a protected digest key and CopyObject into a
	// non-protected canary prefix. Without these positive controls a 403
	// might reflect missing source read or destination write permissions.
	copier, err := New(Config{Endpoint: endpoint, Bucket: bucket, Region: region, AccessKey: copyAccess, SecretKey: copySecret})
	if err != nil {
		t.Fatalf("approved copy-capable fixture config: %v", err)
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
		Path:      "reports/approved-writeonce-gate.md",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		SizeBytes: int64(len(original)),
	}
	const tenant, workspaceID = "tenant-security-probe", "workspace-writeonce-probe"
	key, err := writer.objectPath(tenant, workspaceID, asset.Digest)
	if err != nil {
		t.Fatal(err)
	}

	if status := rawS3Status(t, ctx, writer, http.MethodPut, key, original, true); status != http.StatusOK {
		t.Fatalf("approved provider rejected initial conditional PUT: HTTP %d", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, asset); err != nil {
		t.Fatalf("approved provider did not return correct initial bytes: %v", err)
	}
	if status := rawS3Status(t, ctx, writer, http.MethodPut, key, original, true); status != http.StatusPreconditionFailed {
		t.Fatalf("approved provider must reject existing-key conditional PUT as 412, got %d", status)
	}

	// A policy that blocks only replacement of known existing keys would
	// appear safe in the basic test, but still allows NEW unconditioned
	// objects. Enforce If-None-Match for the entire digest prefix, then
	// prove legitimate conditional creation of that same previously absent
	// key works. This distinguishes a true conditional-write policy from a
	// blanket PutObject denial.
	fresh := []byte(fmt.Sprintf("P0-2B5c raw first-write bypass canary=%x", nonce))
	freshDigest := sha256.Sum256(fresh)
	freshAsset := workspace.Asset{
		Path:      "reports/approved-fresh-key-policy.md",
		Digest:    "sha256:" + hex.EncodeToString(freshDigest[:]),
		SizeBytes: int64(len(fresh)),
	}
	freshKey, err := writer.objectPath(tenant, workspaceID, freshAsset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if status := rawS3Status(t, ctx, writer, http.MethodPut, freshKey, fresh, false); status != http.StatusForbidden {
		t.Fatalf("P0 CONDITIONAL POLICY FAILURE: unconditioned FIRST PUT of fresh digest key returned %d instead of provider 403", status)
	}
	if status := rawS3Status(t, ctx, writer, http.MethodPut, freshKey, fresh, true); status != http.StatusOK {
		t.Fatalf("policy denies valid conditional first PUT after raw 403: HTTP %d", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, freshAsset); err != nil {
		t.Fatalf("first conditional PUT after denied raw write did not preserve verified bytes: %v", err)
	}
	if status := rawS3Status(t, ctx, writer, http.MethodPut, freshKey, fresh, false); status != http.StatusForbidden {
		t.Fatalf("fresh digest key became unconditionally overwriteable after creation: HTTP %d", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, freshAsset); err != nil {
		t.Fatalf("fresh digest key changed after denied unconditional overwrite: %v", err)
	}

	different := bytes.Clone(original)
	different[0] ^= 0x01
	// Reject a compliant conditional PUT carrying DIFFERENT bytes too.
	// A 412 must leave the original object immutable regardless of payload.
	if status := rawS3Status(t, ctx, writer, http.MethodPut, key, different, true); status != http.StatusPreconditionFailed {
		t.Fatalf("conditional altered-payload replay changed the digest key: HTTP %d (want 412)", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, asset); err != nil {
		t.Fatalf("conditional altered-payload replay changed original bytes: %v", err)
	}
	// Send an independently built raw *signed* S3 PUT WITHOUT If-None-Match, deliberately
	// bypassing every ACP convenience upload method. Only the backend IAM
	// policy can block this attempt. A 200 here is an immediate hard FAIL.
	if status := rawS3Status(t, ctx, writer, http.MethodPut, key, different, false); status != http.StatusForbidden {
		t.Fatalf("P0 WRITE-ONCE FAILURE: valid scoped writer unconditionally re-PUT same key (status=%d, want provider 403)", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, asset); err != nil {
		t.Fatalf("write-once denial did not preserve immutable original bytes: %v", err)
	}
	if status := rawS3Status(t, ctx, writer, http.MethodDelete, key, nil, false); status != http.StatusForbidden {
		t.Fatalf("scoped writer could DELETE object despite WORM acceptance: HTTP %d", status)
	}
	if status := rawS3Status(t, ctx, reader, http.MethodPut, key, different, false); status != http.StatusForbidden {
		t.Fatalf("read-only identity could overwrite object: HTTP %d", status)
	}
	foreignKey, err := writer.objectPath("tenant-other-probe", workspaceID, asset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if status := rawS3Status(t, ctx, writer, http.MethodPut, foreignKey, original, true); status != http.StatusForbidden {
		t.Fatalf("scoped writer could cross tenant boundary: HTTP %d", status)
	}
	// A trusted reader has access only to its tenant and workspace prefix.
	// This checks provider IAM, not ACP's in-process lock validation.
	if status := rawS3Status(t, ctx, reader, http.MethodGet, foreignKey, nil, false); status != http.StatusForbidden {
		t.Fatalf("read-only identity could GET a foreign tenant prefix: HTTP %d", status)
	}
	for _, role := range []*Store{writer, reader} {
		if status := rawS3Status(t, ctx, role, http.MethodGet, "/", nil, false); status != http.StatusForbidden {
			t.Fatalf("scoped principal could enumerate buckets: HTTP %d", status)
		}
	}
	// Do not use an unsigned response code as evidence of conditional
	// write-once enforcement; it is solely an additional auth negative.
	unsigned, err := http.NewRequestWithContext(ctx, http.MethodGet, reader.endpoint.String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	unsignedResp, err := reader.client.Do(unsigned)
	if err != nil {
		t.Fatalf("unsigned S3 request failed before provider authorization: %v", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(unsignedResp.Body, 4096))
	_ = unsignedResp.Body.Close()
	if unsignedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("unsigned request unexpectedly received HTTP %d", unsignedResp.StatusCode)
	}

	// COPY bypass matrix uses a third, deliberately COPY-capable IAM identity.
	// First prove source read + non-protected destination CopyObject actually
	// work, and that this SAME identity can conditionally create a protected
	// digest key. A denied COPY without these controls proves nothing about
	// enforcement of the protected destination's bucket policy.
	copyPositivePath := fmt.Sprintf("/%s/validation/copy-positive/%x", bucket, nonce)
	copyStatus, copyXML := rawS3CopyStatus(t, ctx, copier, copyPositivePath, freshKey)
	if copyStatus != http.StatusOK || !strings.Contains(copyXML, "<CopyObjectResult") {
		t.Fatalf("COPY positive control missing: HTTP %d; copy principal needs real source GET and scratch destination PUT", copyStatus)
	}
	if copied := rawS3ReadCopyCanary(t, ctx, copier, copyPositivePath); !bytes.Equal(copied, fresh) {
		t.Fatal("COPY positive control did not retain exact source bytes")
	}
	copyAllowedBytes := []byte(fmt.Sprintf("P0-2B5g scoped copier conditional PUT canary=%x", nonce))
	copyAllowedDigest := sha256.Sum256(copyAllowedBytes)
	copyAllowedAsset := workspace.Asset{
		Path: "reports/copier-allowed-conditional-put.md",
		Digest: "sha256:" + hex.EncodeToString(copyAllowedDigest[:]),
		SizeBytes: int64(len(copyAllowedBytes)),
	}
	copyAllowedKey, err := copier.objectPath(tenant, workspaceID, copyAllowedAsset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if status := rawS3Status(t, ctx, copier, http.MethodPut, copyAllowedKey, copyAllowedBytes, true); status != http.StatusOK {
		t.Fatalf("COPY principal lacks positive conditional-PUT rights on protected prefix: HTTP %d", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, copyAllowedAsset); err != nil {
		t.Fatalf("COPY principal's protected conditional-PUT bytes were not verified: %v", err)
	}

	// Source and destination differ: a provider cannot short-circuit the
	// test as an invalid same-key self-copy. The source's bytes differ
	// from the destination's content-addressed digest.
	if status, _ := rawS3CopyStatus(t, ctx, copier, key, freshKey); status != http.StatusForbidden {
		t.Fatalf("P0 COPY WORM FAILURE: unconditioned CopyObject into existing protected digest returned %d (want server 403)", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, asset); err != nil {
		t.Fatalf("denied COPY into existing digest corrupted original: %v", err)
	}

	copyFreshBytes := []byte(fmt.Sprintf("P0-2B5g COPY absent-key canary=%x", nonce))
	copyFreshDigest := sha256.Sum256(copyFreshBytes)
	copyFreshAsset := workspace.Asset{
		Path: "reports/copy-absent-key-policy.md",
		Digest: "sha256:" + hex.EncodeToString(copyFreshDigest[:]),
		SizeBytes: int64(len(copyFreshBytes)),
	}
	copyFreshKey, err := copier.objectPath(tenant, workspaceID, copyFreshAsset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := rawS3CopyStatus(t, ctx, copier, copyFreshKey, freshKey); status != http.StatusForbidden {
		t.Fatalf("P0 COPY WORM FAILURE: unconditioned CopyObject into ABSENT protected digest returned %d (want server 403)", status)
	}
	if _, err := reader.ReadAsset(ctx, tenant, workspaceID, copyFreshAsset); !errors.Is(err, ErrObjectMissing) {
		t.Fatalf("denied COPY into absent digest left unexpected object or storage error: %v", err)
	}
	if status := rawS3Status(t, ctx, copier, http.MethodPut, copyFreshKey, copyFreshBytes, true); status != http.StatusOK {
		t.Fatalf("protected fresh COPY destination rejected legitimate conditional PUT: HTTP %d", status)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, copyFreshAsset); err != nil {
		t.Fatalf("conditional PUT after denied COPY failed to retain verified bytes: %v", err)
	}
	t.Log("APPROVED COPY WORM CONTRACT PASS: copy-capable principal passed actual source COPY/GET and protected conditional PUT positive controls, while raw existing/fresh protected CopyObject both returned 403")

	// Independent concurrent first-writer attempts against the SAME digest
	// must produce one created object and three rejected conditional PUTs.
	// This is additional evidence against multi-writer clobbering, not
	// proof of Object Lock or version-pinned historical reads.
	racingBytes := []byte(fmt.Sprintf("P0-2B5c simultaneous digest creation canary=%x", nonce))
	racingDigest := sha256.Sum256(racingBytes)
	racingAsset := workspace.Asset{
		Path:      "reports/concurrent-writeonce-gate.md",
		Digest:    "sha256:" + hex.EncodeToString(racingDigest[:]),
		SizeBytes: int64(len(racingBytes)),
	}
	racingKey, err := writer.objectPath(tenant, workspaceID, racingAsset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	type responseResult struct {
		status int
		err    error
	}
	resultChannel := make(chan responseResult, 4)
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			<-start
			req, e := rawS3SignedRequest(ctx, writer, http.MethodPut, racingKey, racingBytes, true)
			if e != nil {
				resultChannel <- responseResult{err: e}
				return
			}
			resp, e := writer.client.Do(req)
			if e != nil {
				resultChannel <- responseResult{err: e}
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			resultChannel <- responseResult{status: resp.StatusCode}
		}()
	}
	close(start)
	created, rejected := 0, 0
	for i := 0; i < 4; i++ {
		got := <-resultChannel
		if got.err != nil {
			t.Fatalf("concurrent provider PUT failed: %v", got.err)
		}
		switch got.status {
		case http.StatusOK:
			created++
		case http.StatusPreconditionFailed:
			rejected++
		default:
			t.Fatalf("concurrent PUT returned unsupported status %d", got.status)
		}
	}
	if created != 1 || rejected != 3 {
		t.Fatalf("concurrent same-key PUT must have exactly one 200 and three 412: created=%d rejected=%d", created, rejected)
	}
	if err := reader.VerifyAsset(ctx, tenant, workspaceID, racingAsset); err != nil {
		t.Fatalf("concurrent first-writer asset did not retain verified bytes: %v", err)
	}
	// Even if a future object-store implementation reports an error for
	// 403, it must remain distinguishable from a missing object.
	if err := writer.VerifyAsset(ctx, tenant, workspaceID, asset); !errors.Is(err, ErrStorage) {
		t.Fatalf("write-only principal GET denial must be ErrStorage, got %v", err)
	}
	t.Log("APPROVED S3 WORM CONTRACT PASS: unconditional fresh-key and same-key PUT both 403; conditional new key 200, duplicate/altered conditional PUT 412; original bytes preserved; tenant scope, bucket listing and DELETE denied")
}
