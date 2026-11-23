package postfault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	AgentDEvidenceReadPath   = "/v1/agentd/evidence:read"
	AgentDEvidenceReadSchema = "acp.agentd-evidence-export/v1"
	maxAgentDEvidenceBody    = 4 << 20
	maxAgentDEvidenceEvents  = 256
)

var (
	ErrAgentDEvidenceUnavailable = errors.New("independent AgentD source evidence unavailable or invalid")
	ErrAgentDEvidenceUnresolved  = errors.New("original AgentD process remains UNKNOWN/HOLD")
)

type AgentDEvidenceReadRequest struct {
	Ref AgentDWaitRef `json:"ref"`
}

type AgentDEvidenceRecord struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
	Digest       string `json:"digest"`
}

// Head deliberately has the same default JSON field names as the source
// AgentD InspectHead. It is compared to a separately pinned consumer value;
// a Head supplied by this HTTP response is never its own trust anchor.
type AgentDEvidenceReadResponse struct {
	Schema      string        `json:"schema"`
	Ref         AgentDWaitRef `json:"ref"`
	State       string        `json:"state"`
	NextAction  string        `json:"next_action"`
	Head        TrustedAgentDInspectHead `json:"head"`
	Inspections []AgentDEvidenceRecord `json:"inspections"`
	Terminal    *AgentDEvidenceRecord  `json:"terminal,omitempty"`
	CanRetry    bool                   `json:"can_retry"`
}

// AgentDEvidenceClient fetches only the bounded original AgentD evidence
// export. Endpoint is trusted deployment configuration, never a request or
// model field. HTTPClient must carry the mTLS client certificate and trust
// the server certificate for the configured endpoint.
type AgentDEvidenceClient struct {
	Endpoint   string
	HTTPClient *http.Client
}

func validAgentDEvidenceRef(ref AgentDWaitRef) bool {
	return safeID(ref.TenantID) && safeID(ref.RunID) &&
		safeID(ref.RuntimeAttemptID) && safeID(ref.SandboxUID) &&
		safeID(ref.CommandID) && safeID(ref.AttemptID) &&
		safeID(ref.ProviderCommandUID) && safeID(ref.GuardPermitID) &&
		safeID(ref.HostBootID) && validDigest(ref.RequestDigest) &&
		ref.PermitEpoch > 0 && ref.ProcessPID > 0 && ref.ProcessStartTicks > 0
}

func (c AgentDEvidenceClient) endpointURL() (string, error) {
	if c.Endpoint == "" || c.HTTPClient == nil {
		return "", ErrAgentDEvidenceUnavailable
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", ErrAgentDEvidenceUnavailable
	}
	u.Path = AgentDEvidenceReadPath
	return u.String(), nil
}

func (c AgentDEvidenceClient) httpClient() *http.Client {
	client := *c.HTTPClient
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if client.Timeout <= 0 {
		client.Timeout = 5 * time.Second
	}
	return &client
}

// Read validates transport metadata, canonical response JSON, exact original
// Ref and independently pinned Head, complete event count, per-record content
// digests, HOLD semantics and terminal-presence consistency. Cryptographic
// signature and cross-authority checks are performed by Verify below.
func (c AgentDEvidenceClient) Read(ctx context.Context, ref AgentDWaitRef,
	trustedHead TrustedAgentDInspectHead) (AgentDEvidenceReadResponse, error) {
	var empty AgentDEvidenceReadResponse
	if ctx == nil || !validAgentDEvidenceRef(ref) ||
		trustedHead.InspectCount == 0 ||
		trustedHead.JournalVersion != trustedHead.InspectCount ||
		trustedHead.InspectCount > maxAgentDEvidenceEvents ||
		!validDigest(trustedHead.Digest) {
		return empty, ErrAgentDEvidenceUnavailable
	}
	endpoint, err := c.endpointURL()
	if err != nil {
		return empty, err
	}
	requestBody, err := json.Marshal(AgentDEvidenceReadRequest{Ref: ref})
	if err != nil {
		return empty, ErrAgentDEvidenceUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return empty, ErrAgentDEvidenceUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := c.httpClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return empty, ctx.Err()
		}
		return empty, ErrAgentDEvidenceUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return empty, ErrAgentDEvidenceUnavailable
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" ||
		!strings.Contains(strings.ToLower(response.Header.Get("Cache-Control")), "no-store") {
		return empty, ErrAgentDEvidenceUnavailable
	}
	if encoding := strings.TrimSpace(strings.ToLower(response.Header.Get("Content-Encoding"))); encoding != "" && encoding != "identity" {
		return empty, ErrAgentDEvidenceUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxAgentDEvidenceBody+1))
	if err != nil {
		if ctx.Err() != nil {
			return empty, ctx.Err()
		}
		return empty, ErrAgentDEvidenceUnavailable
	}
	if len(raw) == 0 || len(raw) > maxAgentDEvidenceBody {
		return empty, ErrAgentDEvidenceUnavailable
	}
	var decoded AgentDEvidenceReadResponse
	if !StrictDecode(bytes.TrimSpace(raw), &decoded) {
		return empty, ErrAgentDEvidenceUnavailable
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) ||
		decoded.Schema != AgentDEvidenceReadSchema || decoded.Ref != ref ||
		decoded.Head != trustedHead || decoded.NextAction != "HOLD" ||
		decoded.CanRetry || len(decoded.Inspections) == 0 ||
		len(decoded.Inspections) != int(trustedHead.InspectCount) ||
		len(decoded.Inspections) > maxAgentDEvidenceEvents {
		return empty, ErrAgentDEvidenceUnavailable
	}
	switch decoded.State {
	case "UNKNOWN":
		if decoded.Terminal != nil {
			return empty, ErrAgentDEvidenceUnavailable
		}
	case "EXITED", "FAILED_CONFIRMED":
		if decoded.Terminal == nil {
			return empty, ErrAgentDEvidenceUnavailable
		}
	default:
		return empty, ErrAgentDEvidenceUnavailable
	}
	var last AgentDInspectEvent
	for i, record := range decoded.Inspections {
		if _, err := decodeAgentDEvidenceRecord(record); err != nil {
			return empty, ErrAgentDEvidenceUnavailable
		}
		if i == len(decoded.Inspections)-1 {
			envelope, _ := decodeAgentDEvidenceRecord(record)
			if !strictSourceInspect(envelope.Payload, &last) ||
				last.Ref != ref || last.InspectCount != uint64(len(decoded.Inspections)) ||
				last.JournalVersion != last.InspectCount || last.State != decoded.State ||
				last.NextAction != "HOLD" {
				return empty, ErrAgentDEvidenceUnavailable
			}
		}
	}
	if decoded.Terminal != nil {
		if _, err := decodeAgentDEvidenceRecord(*decoded.Terminal); err != nil {
			return empty, ErrAgentDEvidenceUnavailable
		}
	}
	return decoded, nil
}

func decodeAgentDEvidenceRecord(record AgentDEvidenceRecord) (SignedAgentDInspect, error) {
	var empty SignedAgentDInspect
	payload, err := base64.StdEncoding.Strict().DecodeString(record.PayloadB64)
	if err != nil || len(payload) == 0 || len(payload) > maxObservationSize ||
		!validDigest(record.Digest) || inspectSourceDigest(payload) != record.Digest {
		return empty, ErrAgentDEvidenceUnavailable
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(record.SignatureB64)
	if err != nil || len(signature) != 64 {
		return empty, ErrAgentDEvidenceUnavailable
	}
	return SignedAgentDInspect{Payload: payload, Signature: signature}, nil
}

// Verify fetches the original source export over the caller-configured mTLS
// transport and joins its exact signed bytes to the independent G05 bundle,
// ExpectedAgentDWait and trusted Head. UNKNOWN/HOLD remains unresolved and
// cannot be promoted to recovery success.
func (c AgentDEvidenceClient) Verify(ctx context.Context, b Bundle,
	keys map[string]ed25519.PublicKey, expected ExpectedAgentDWait,
	trustedHead TrustedAgentDInspectHead, now time.Time) error {
	response, err := c.Read(ctx, expected.Ref, trustedHead)
	if err != nil {
		return err
	}
	if response.State == "UNKNOWN" {
		return ErrAgentDEvidenceUnresolved
	}
	events := make([]SignedAgentDInspect, 0, len(response.Inspections))
	for _, record := range response.Inspections {
		event, err := decodeAgentDEvidenceRecord(record)
		if err != nil {
			return ErrAgentDEvidenceUnavailable
		}
		events = append(events, event)
	}
	if response.Terminal == nil {
		return ErrAgentDEvidenceUnavailable
	}
	terminal, err := decodeAgentDEvidenceRecord(*response.Terminal)
	if err != nil {
		return ErrAgentDEvidenceUnavailable
	}
	return VerifyWithAgentDSourceJournal(b, keys, expected, terminal.Payload,
		terminal.Signature, events, trustedHead, now)
}
