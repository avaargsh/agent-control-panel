// Package runtimeinspect provides a read-only, workload-authenticated
// Agent Control Plane to Runtime RunIntent inspection boundary.
// Runtime owns Run identity; ABSENT_UNCERTAIN never authorizes retry.
package runtimeinspect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalidConfig   = errors.New("invalid Runtime Inspect client trust configuration")
	ErrInvalidRequest  = errors.New("invalid RunIntent inspection scope")
	ErrInvalidResponse = errors.New("invalid or untrusted Runtime Inspect response")
	ErrRemoteDenied    = errors.New("Runtime Inspect rejected authenticated service")
	ErrRemoteConflict  = errors.New("Runtime Inspect identity conflict")
	ErrUnavailable     = errors.New("Runtime Inspect unavailable or indeterminate")
)

type Status string

const (
	Found           Status = "FOUND"
	AbsentUncertain Status = "ABSENT_UNCERTAIN"
)

const (
	inspectPath      = "/internal/v1/run-intents/"
	maxResponseBytes = 4096
)

var (
	canonicalUUID = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
	digestSHA256   = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
)

type InspectRequest struct {
	TenantID      string
	RunIntentID   string
	RequestDigest string
}

func (r InspectRequest) Validate() error {
	if r.TenantID == "" || len(r.TenantID) > 255 ||
		strings.TrimSpace(r.TenantID) != r.TenantID ||
		!utf8.ValidString(r.TenantID) ||
		strings.ContainsAny(r.TenantID, "\x00\r\n\t") ||
		!canonicalUUID.MatchString(r.RunIntentID) ||
		!digestSHA256.MatchString(r.RequestDigest) {
		return ErrInvalidRequest
	}
	return nil
}

type Inspection struct {
	Status        Status
	TenantID      string
	RunIntentID   string
	RequestDigest string
	RunID         string
	WorkflowID    string
}

// Client is intentionally read-only; a Runtime response cannot mint a
// NOT_FOUND_FINAL proof or an authorization to issue a second StartRun.
type Client struct {
	base   string
	client *http.Client
}

// NewClient requires both a trusted server certificate chain and one exact
// Runtime SPIFFE URI SAN. The supplied client certificate represents the ACP
// workload, never the initiating subject/actor or a human bearer token.
//
// The HTTPS origin must have an ordinary DNS/IP name matching the server
// certificate, in addition to the expected Runtime SPIFFE URI SAN.
func NewClient(originRaw, expectedRuntimeSPIFFE string, roots *x509.CertPool, clientIdentity tls.Certificate) (*Client, error) {
	origin, err := url.Parse(originRaw)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" ||
		origin.User != nil || origin.Path != "" || origin.RawPath != "" ||
		origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" ||
		origin.String() != originRaw || roots == nil ||
		len(clientIdentity.Certificate) == 0 || clientIdentity.PrivateKey == nil {
		return nil, ErrInvalidConfig
	}
	spiffe, err := url.Parse(expectedRuntimeSPIFFE)
	if err != nil || spiffe.Scheme != "spiffe" || spiffe.Host == "" ||
		spiffe.Path == "" || spiffe.Path == "/" || spiffe.User != nil ||
		spiffe.Opaque != "" || spiffe.RawPath != "" ||
		spiffe.RawQuery != "" || spiffe.ForceQuery || spiffe.Fragment != "" ||
		spiffe.String() != expectedRuntimeSPIFFE {
		return nil, ErrInvalidConfig
	}
	config := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		RootCAs:          roots,
		Certificates:     []tls.Certificate{clientIdentity},
		ServerName:       origin.Hostname(),
		VerifyConnection: func(state tls.ConnectionState) error {
			if !state.HandshakeComplete || state.Version < tls.VersionTLS13 ||
				len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
				return ErrInvalidResponse
			}
			leaf := state.PeerCertificates[0]
			if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0] == nil ||
				leaf.URIs[0].String() != expectedRuntimeSPIFFE {
				return ErrInvalidResponse
			}
			for _, chain := range state.VerifiedChains {
				if len(chain) > 0 && chain[0] != nil && bytes.Equal(chain[0].Raw, leaf.Raw) {
					return nil
				}
			}
			return ErrInvalidResponse
		},
	}
	transport := &http.Transport{
		TLSClientConfig:       config,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		Proxy:                 nil, // no environment-controlled proxy for privileged traffic
	}
	return &Client{
		base: originRaw,
		client: &http.Client{
			Transport: transport,
			Timeout:   12 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Inspect returns FOUND only for the exact authoritative correlation scope.
// ABSENT_UNCERTAIN represents no committed record observed; it is not an
// authoritative final absence and must not authorize UNKNOWN -> PENDING.
func (c *Client) Inspect(ctx context.Context, scope InspectRequest) (Inspection, error) {
	if c == nil || c.client == nil || c.base == "" {
		return Inspection{}, ErrInvalidConfig
	}
	if err := scope.Validate(); err != nil {
		return Inspection{}, err
	}
	query := url.Values{}
	query.Set("tenant_id", scope.TenantID)
	query.Set("request_digest", scope.RequestDigest)
	endpoint := c.base + inspectPath + url.PathEscape(scope.RunIntentID) + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Inspection{}, fmt.Errorf("%w: build lookup: %v", ErrInvalidRequest, err)
	}
	req.Header.Set("Accept", "application/json")
	// No Authorization header, forwarded identity or request body is accepted.
	res, err := c.client.Do(req)
	if err != nil {
		return Inspection{}, fmt.Errorf("%w: transport: %v", ErrUnavailable, err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return Inspection{}, ErrRemoteDenied
	case http.StatusConflict:
		return Inspection{}, ErrRemoteConflict
	default:
		return Inspection{}, ErrUnavailable
	}
	media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return Inspection{}, ErrInvalidResponse
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxResponseBytes {
		return Inspection{}, ErrInvalidResponse
	}
	return parseInspectResponse(raw, scope)
}

func parseInspectResponse(raw []byte, scope InspectRequest) (Inspection, error) {
	if err := scope.Validate(); err != nil || len(raw) == 0 || len(raw) > maxResponseBytes {
		return Inspection{}, ErrInvalidResponse
	}
	fields, err := uniqueObject(raw)
	if err != nil {
		return Inspection{}, ErrInvalidResponse
	}
	status, ok := stringField(fields, "status")
	if !ok {
		return Inspection{}, ErrInvalidResponse
	}
	switch Status(status) {
	case AbsentUncertain:
		if len(fields) != 1 {
			return Inspection{}, ErrInvalidResponse
		}
		return Inspection{Status: AbsentUncertain}, nil
	case Found:
		if len(fields) != 7 {
			return Inspection{}, ErrInvalidResponse
		}
		tenant, a := stringField(fields, "tenant_id")
		intent, b := stringField(fields, "run_intent_id")
		digest, d := stringField(fields, "request_digest")
		runID, e := stringField(fields, "run_id")
		workflow, f := stringField(fields, "workflow_id")
		created, g := fields["created"]
		if !a || !b || !d || !e || !f || !g ||
			(string(created) != "true" && string(created) != "false") ||
			tenant != scope.TenantID || intent != scope.RunIntentID ||
			digest != scope.RequestDigest || !canonicalUUID.MatchString(runID) ||
			workflow != "agent-run/v1/"+runID {
			return Inspection{}, ErrInvalidResponse
		}
		return Inspection{
			Status: Found, TenantID: tenant, RunIntentID: intent,
			RequestDigest: digest, RunID: runID, WorkflowID: workflow,
		}, nil
	default:
		// The current Runtime does not support NOT_FOUND_FINAL. In particular,
		// never interpret HTTP 404 or ABSENT_UNCERTAIN as final absence.
		return Inspection{}, ErrInvalidResponse
	}
}

func stringField(fields map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := fields[name]
	if !ok || len(raw) < 2 || raw[0] != '"' {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || value == "" {
		return "", false
	}
	return value, true
}

// uniqueObject rejects duplicate top-level keys, non-objects and trailing
// JSON. Only simple typed values are accepted by parseInspectResponse.
func uniqueObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return nil, ErrInvalidResponse
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, ErrInvalidResponse
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, ErrInvalidResponse
		}
		if _, exists := fields[key]; exists {
			return nil, ErrInvalidResponse
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, ErrInvalidResponse
		}
		fields[key] = value
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return nil, ErrInvalidResponse
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrInvalidResponse
	}
	return fields, nil
}
