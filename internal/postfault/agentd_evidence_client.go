package postfault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"
)

const (
	AgentDEvidenceReadPath   = "/v1/agentd/evidence:read"
	AgentDEvidenceReadSchema = "acp.agentd-evidence-export/v1"
	maxAgentDWireBytes       = 4 << 20
	maxAgentDWireEvents      = 256
	maxAgentDSourceBytes     = 8192
)

type AgentDWireRecord struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
	Digest       string `json:"digest"`
}

// The AgentD source uses Go's default upper-case field names for the Head
// struct. Do not silently rename source wire keys during verification.
type AgentDWireHead struct {
	InspectCount   uint64 `json:"InspectCount"`
	JournalVersion uint64 `json:"JournalVersion"`
	Digest         string `json:"Digest"`
}

type AgentDEvidenceResponse struct {
	Schema      string             `json:"schema"`
	Ref         AgentDWaitRef      `json:"ref"`
	State       string             `json:"state"`
	NextAction  string             `json:"next_action"`
	Head        AgentDWireHead     `json:"head"`
	Inspections []AgentDWireRecord `json:"inspections"`
	Terminal    *AgentDWireRecord  `json:"terminal,omitempty"`
	CanRetry    bool               `json:"can_retry"`
}

func validEvidenceTLSIdentity(cfg *tls.Config, expected AgentDWaitRef) bool {
	if cfg == nil || cfg.InsecureSkipVerify || cfg.RootCAs == nil ||
		len(cfg.Certificates) != 1 || len(cfg.Certificates[0].Certificate) == 0 ||
		cfg.Certificates[0].PrivateKey == nil || cfg.MinVersion < tls.VersionTLS13 {
		return false
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil || len(leaf.URIs) != 1 {
		return false
	}
	identity := leaf.URIs[0]
	if identity.Scheme != "spiffe" || identity.Host == "" ||
		identity.User != nil || identity.RawQuery != "" || identity.Fragment != "" {
		return false
	}
	// Protect against accidentally sending original Run evidence to a peer
	// under a different tenant/Run or a privileged executor role. The server
	// independently checks its configured trust domain and peer certificate.
	wantPath := "/tenant/" + url.PathEscape(expected.TenantID) +
		"/run/" + url.PathEscape(expected.RunID) + "/role/evidence-reader"
	return identity.EscapedPath() == wantPath
}

func sourceWireRecord(record AgentDWireRecord) ([]byte, []byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(record.PayloadB64)
	if err != nil || len(raw) == 0 || len(raw) > maxAgentDSourceBytes ||
		!validDigest(record.Digest) || inspectSourceDigest(raw) != record.Digest {
		return nil, nil, failure("invalid original AgentD raw signed payload or digest")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(record.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, nil, failure("invalid original AgentD detached source signature")
	}
	return raw, signature, nil
}

func decodeAgentDWire(raw []byte, expected AgentDWaitRef,
	head TrustedAgentDInspectHead) ([]SignedAgentDInspect, []byte, []byte, error) {
	var wire AgentDEvidenceResponse
	if len(raw) == 0 || len(raw) > maxAgentDWireBytes || !StrictDecode(raw, &wire) {
		return nil, nil, nil, failure("AgentD response is ambiguous or oversized")
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) ||
		wire.Schema != AgentDEvidenceReadSchema || wire.Ref != expected ||
		wire.State != "EXITED" && wire.State != "FAILED_CONFIRMED" ||
		wire.NextAction != "HOLD" || wire.CanRetry ||
		wire.Head.InspectCount != head.InspectCount ||
		wire.Head.JournalVersion != head.JournalVersion ||
		wire.Head.Digest != head.Digest ||
		len(wire.Inspections) < 2 || len(wire.Inspections) > maxAgentDWireEvents ||
		wire.Terminal == nil {
		return nil, nil, nil, failure("AgentD source export identity, status or trusted Head mismatch")
	}
	observations := make([]SignedAgentDInspect, 0, len(wire.Inspections))
	for _, record := range wire.Inspections {
		raw, signature, err := sourceWireRecord(record)
		if err != nil {
			return nil, nil, nil, err
		}
		observations = append(observations, SignedAgentDInspect{
			Payload: raw, Signature: signature,
		})
	}
	waitRaw, waitSignature, err := sourceWireRecord(*wire.Terminal)
	if err != nil {
		return nil, nil, nil, err
	}
	// The last Inspect source state must match the export wrapper; the
	// entire signed source chain and Wait are checked again by G05.
	var final AgentDInspectEvent
	if !strictSourceInspect(observations[len(observations)-1].Payload, &final) ||
		final.State != wire.State || final.ExitReceiptDigest != wire.Terminal.Digest {
		return nil, nil, nil, failure("signed AgentD Inspect and export terminal disagree")
	}
	return observations, waitRaw, waitSignature, nil
}

// FetchAndVerifyAgentDEvidence is a read-only ACP consumer. The endpoint,
// TLS trust roots, authorized Run/Attempt/Guard tuple, independent public
// signing keys, and trusted Head must all come from out-of-band authorized
// control-plane state, NEVER from a model, HTTP response or candidate Journal.
//
// The consumer refuses redirects and plaintext HTTP, authenticates the
// server's TLS certificate against the explicitly supplied RootCAs and sends
// exactly one evidence-reader client identity. It does not mint Inspect
// events, dispatch/retry a command, issue Permits or release any resource.
func FetchAndVerifyAgentDEvidence(ctx context.Context, endpoint string, credentials *tls.Config,
	b Bundle, keys map[string]ed25519.PublicKey, expected ExpectedAgentDWait,
	head TrustedAgentDInspectHead, now time.Time) error {
	uri, err := url.Parse(endpoint)
	if err != nil || uri.Scheme != "https" || uri.Host == "" ||
		uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" ||
		uri.Path != AgentDEvidenceReadPath ||
		!validEvidenceTLSIdentity(credentials, expected.Ref) ||
		!validDigest(head.Digest) || head.InspectCount == 0 ||
		head.JournalVersion != head.InspectCount ||
		len(keys["agentd"]) != ed25519.PublicKeySize ||
		b.Subject.TenantID != expected.Ref.TenantID ||
		b.Subject.RunID != expected.Ref.RunID ||
		b.Subject.GuardOperationID != expected.GuardOperationID {
		return failure("untrusted AgentD mTLS target or independent Run/Head binding")
	}
	request, err := json.Marshal(struct {
		Ref AgentDWaitRef `json:"ref"`
	}{Ref: expected.Ref})
	if err != nil {
		return failure("cannot serialize original AgentD attempt")
	}
	transport := &http.Transport{
		TLSClientConfig:     credentials.Clone(),
		Proxy:               nil,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), bytes.NewReader(request))
	if err != nil {
		return failure("invalid AgentD evidence request")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := client.Do(httpRequest)
	if err != nil {
		return failure("authenticated AgentD transport unavailable")
	}
	defer response.Body.Close()
	contentType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil ||
		contentType != "application/json" ||
		response.Header.Get("Cache-Control") != "no-store" ||
		response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return failure("AgentD response not authenticated or complete")
	}
	wireRaw, err := io.ReadAll(io.LimitReader(response.Body, maxAgentDWireBytes+1))
	if err != nil || len(wireRaw) > maxAgentDWireBytes {
		return failure("AgentD source response truncated or exceeds security bound")
	}
	inspectSource, waitRaw, waitSig, err := decodeAgentDWire(wireRaw, expected.Ref, head)
	if err != nil {
		return err
	}
	// This final gate validates every existing signed G05 authority, the
	// independently signed original OS Wait, the complete monotonic AgentD
	// Inspect journal and the externally pinned exact Head. No fallback.
	return VerifyWithAgentDSourceJournal(b, keys, expected, waitRaw, waitSig,
		inspectSource, head, now)
}
