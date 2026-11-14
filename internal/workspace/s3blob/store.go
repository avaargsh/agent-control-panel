// Package s3blob provides a deliberately narrow S3 path-style SigV4 byte
// adapter. It is internal-only: callers must authenticate tenant/Workspace
// scope against ACP before invoking it and keep credentials server-side.
package s3blob

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/workspace"
)

const MaxUploadBytes int64 = 8 << 20

var (
	ErrInvalidConfig  = errors.New("invalid S3 backend configuration")
	ErrInvalidObject  = errors.New("invalid scoped Workspace object")
	ErrIntegrity      = errors.New("Workspace object bytes fail digest/size verification")
	ErrObjectMissing  = errors.New("Workspace object missing")
	ErrStorage        = errors.New("S3 backend operation failed")
)

type Config struct {
	Endpoint          string
	Region            string
	Bucket            string
	AccessKey         string
	SecretKey         string
	SessionToken      string
	AllowHTTPForTests bool // only loopback; never permits plaintext remote traffic
	HTTPClient        *http.Client
}

type Store struct {
	endpoint    *url.URL
	region      string
	bucket      string
	accessKey   string
	secretKey   string
	session     string
	client      *http.Client
}

func validRegion(v string) bool {
	if v == "" || len(v) > 63 || strings.HasPrefix(v, "-") || strings.HasSuffix(v, "-") {
		return false
	}
	for _, c := range v {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

func validBucket(v string) bool {
	if len(v) < 3 || len(v) > 63 || v[0] == '-' || v[len(v)-1] == '-' {
		return false
	}
	for _, c := range v {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

// New rejects redirects, untrusted URL components and remote HTTP. This client
// intentionally supports only simple signed PUT and GET of <=8 MiB objects,
// not multipart uploads, bucket creation, list, delete or garbage collection.
func New(c Config) (*Store, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") ||
		(u.Scheme != "https" && u.Scheme != "http") ||
		!validBucket(c.Bucket) || !validRegion(c.Region) ||
		c.AccessKey == "" || c.SecretKey == "" || strings.ContainsAny(c.AccessKey, "\n\r ") {
		return nil, ErrInvalidConfig
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if !c.AllowHTTPForTests || (host != "localhost" && net.ParseIP(host) == nil) {
			return nil, ErrInvalidConfig
		}
		ip := net.ParseIP(host)
		if ip != nil && !ip.IsLoopback() {
			return nil, ErrInvalidConfig
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if c.HTTPClient != nil {
		*client = *c.HTTPClient
		if client.Timeout <= 0 {
			client.Timeout = 30 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	u.Path = ""
	u.RawPath = ""
	return &Store{
		endpoint: u, region: c.Region, bucket: c.Bucket,
		accessKey: c.AccessKey, secretKey: c.SecretKey, session: c.SessionToken,
		client: client,
	}, nil
}

func (s *Store) objectPath(tenant, workspaceID, digest string) (string, error) {
	if s == nil || !workspace.ValidID(tenant) || !workspace.ValidID(workspaceID) ||
		!workspace.ValidDigest(digest) {
		return "", ErrInvalidObject
	}
	return "/" + s.bucket + "/v1/tenant/" + tenant + "/workspace/" + workspaceID +
		"/sha256/" + strings.TrimPrefix(digest, "sha256:"), nil
}

func validateAsset(a workspace.Asset) error {
	_, _, err := workspace.CanonicalManifest([]workspace.Asset{a})
	if err != nil || a.SizeBytes > MaxUploadBytes {
		return ErrInvalidObject
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func signHMAC(key []byte, message string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(message))
	return mac.Sum(nil)
}

func (s *Store) signedRequest(ctx context.Context, method, path string, body []byte, conditional bool) (*http.Request, error) {
	endpoint := *s.endpoint
	endpoint.Path = path
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrStorage
	}
	amzDate := time.Now().UTC().Format("20060102T150405Z")
	shortDate := amzDate[:8]
	payloadHash := sha256Hex(body)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if conditional {
		req.Header.Set("If-None-Match", "*")
	}
	if s.session != "" {
		req.Header.Set("X-Amz-Security-Token", s.session)
	}
	headers := map[string]string{
		"host": req.URL.Host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date": amzDate,
	}
	if conditional {
		headers["if-none-match"] = "*"
	}
	if s.session != "" {
		headers["x-amz-security-token"] = s.session
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, k := range keys {
		canonical.WriteString(k)
		canonical.WriteByte(':')
		canonical.WriteString(headers[k])
		canonical.WriteByte('\n')
	}
	signedNames := strings.Join(keys, ";")
	canonicalRequest := method + "\n" + req.URL.EscapedPath() + "\n\n" +
		canonical.String() + "\n" + signedNames + "\n" + payloadHash
	scope := shortDate + "/" + s.region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	signingKey := signHMAC(signHMAC(signHMAC(signHMAC([]byte("AWS4"+s.secretKey), shortDate), s.region), "s3"), "aws4_request")
	sig := hex.EncodeToString(signHMAC(signingKey, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.accessKey+"/"+scope+
		", SignedHeaders="+signedNames+", Signature="+sig)
	return req, nil
}

// Upload creates a new content-addressed object and immediately re-downloads
// its bytes to confirm integrity. A 412 collision is accepted only if the
// existing immutable key actually contains exactly the requested bytes.
func (s *Store) Upload(ctx context.Context, tenant, workspaceID, logicalPath string, content io.Reader) (workspace.Asset, error) {
	if content == nil || !workspace.ValidID(tenant) || !workspace.ValidID(workspaceID) {
		return workspace.Asset{}, ErrInvalidObject
	}
	// Enforce the same logical path rules as the authoritative Manifest.
	probe := workspace.Asset{Path: logicalPath, Digest: "sha256:" + strings.Repeat("0", 64), SizeBytes: 0}
	if err := validateAsset(probe); err != nil {
		return workspace.Asset{}, err
	}
	data, err := io.ReadAll(io.LimitReader(content, MaxUploadBytes+1))
	if err != nil || int64(len(data)) > MaxUploadBytes {
		return workspace.Asset{}, ErrInvalidObject
	}
	asset := workspace.Asset{Path: logicalPath, Digest: "sha256:" + sha256Hex(data), SizeBytes: int64(len(data))}
	path, err := s.objectPath(tenant, workspaceID, asset.Digest)
	if err != nil {
		return workspace.Asset{}, err
	}
	req, err := s.signedRequest(ctx, http.MethodPut, path, data, true)
	if err != nil {
		return workspace.Asset{}, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return workspace.Asset{}, ErrStorage
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated &&
		resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusPreconditionFailed {
		return workspace.Asset{}, ErrStorage
	}
	if err := s.VerifyAsset(ctx, tenant, workspaceID, asset); err != nil {
		return workspace.Asset{}, err
	}
	return asset, nil
}

// ReadAsset downloads and hashes the *bytes* under a server-derived key. It
// never trusts ETag, user headers, S3 metadata or manifest digest alone.
func (s *Store) ReadAsset(ctx context.Context, tenant, workspaceID string, asset workspace.Asset) ([]byte, error) {
	if err := validateAsset(asset); err != nil {
		return nil, err
	}
	path, err := s.objectPath(tenant, workspaceID, asset.Digest)
	if err != nil {
		return nil, err
	}
	req, err := s.signedRequest(ctx, http.MethodGet, path, nil, false)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, ErrStorage
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrObjectMissing
	}
	if resp.StatusCode != http.StatusOK {
		return nil, ErrStorage
	}
	if resp.ContentLength > MaxUploadBytes {
		return nil, ErrIntegrity
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxUploadBytes+1))
	if err != nil {
		return nil, ErrStorage
	}
	if int64(len(data)) != asset.SizeBytes || int64(len(data)) > MaxUploadBytes ||
		"sha256:"+sha256Hex(data) != asset.Digest {
		return nil, ErrIntegrity
	}
	return data, nil
}

// VerifyAsset implements the ACP Workspace AssetVerifier contract. It reads
// actual scoped bytes; it is not a metadata-only HEAD existence check.
func (s *Store) VerifyAsset(ctx context.Context, tenant, workspaceID string, asset workspace.Asset) error {
	_, err := s.ReadAsset(ctx, tenant, workspaceID, asset)
	return err
}
