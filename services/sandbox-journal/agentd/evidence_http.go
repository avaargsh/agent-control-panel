package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	EvidenceReadPath    = "/v1/agentd/evidence:read"
	EvidenceReadSchema  = "acp.agentd-evidence-export/v1"
	maxEvidenceReadBody = 8192
	maxExportedEvents   = 256
)

// PinnedHeadLookup must independently obtain the accepted, complete source
// Head for this ORIGINAL Run/Attempt, such as from an ACP-held trusted checkpoint.
// Never derive this value from a submitted request, the candidate source DB,
// or the model. No production distribution service is implemented in this PR.
type PinnedHeadLookup func(ctx context.Context, expected Ref) (InspectHead, error)

type EvidenceReadRequest struct {
	Ref Ref `json:"ref"`
}

// SignedSourceRecord transports original bytes without re-encoding a signed
// event. payload_b64 is always the exact original Ed25519 signed payload.
type SignedSourceRecord struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
	Digest       string `json:"digest"`
}

type EvidenceReadResponse struct {
	Schema      string               `json:"schema"`
	Ref         Ref                  `json:"ref"`
	State       string               `json:"state"`
	NextAction  string               `json:"next_action"`
	Head        InspectHead          `json:"head"`
	Inspections []SignedSourceRecord `json:"inspections"`
	Terminal    *SignedSourceRecord  `json:"terminal,omitempty"`
	CanRetry    bool                 `json:"can_retry"`
}

func tlsPeerMatchesOriginal(r *http.Request, expected Ref, domain string) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 ||
		len(r.TLS.PeerCertificates) == 0 || !expected.valid() ||
		domain == "" || strings.ContainsAny(domain, "/?#@:") {
		return false
	}
	leaf := r.TLS.PeerCertificates[0]
	// One SAN only: conflicting or fallback identities are not accepted.
	if len(leaf.URIs) != 1 {
		return false
	}
	want := "spiffe://" + domain +
		"/tenant/" + url.PathEscape(expected.TenantID) +
		"/run/" + url.PathEscape(expected.RunID) +
		"/role/evidence-reader"
	return leaf.URIs[0].String() == want
}

func decodeReadRequest(r *http.Request) (EvidenceReadRequest, int) {
	var req EvidenceReadRequest
	if r.Body == nil {
		return req, http.StatusBadRequest
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return req, http.StatusUnsupportedMediaType
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxEvidenceReadBody+1))
	if err != nil {
		return req, http.StatusBadRequest
	}
	if len(raw) > maxEvidenceReadBody {
		return req, http.StatusRequestEntityTooLarge
	}
	if json.Unmarshal(raw, &req) != nil || !req.Ref.valid() {
		return req, http.StatusBadRequest
	}
	// Strict canonical request shape rejects duplicate fields, unknown
	// metadata, case-folded field aliases and trailing JSON data.
	canonical, err := json.Marshal(req)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return req, http.StatusBadRequest
	}
	return req, 0
}

func signedSource(raw, signature []byte, sourceDigest string) SignedSourceRecord {
	return SignedSourceRecord{
		PayloadB64:   base64.StdEncoding.EncodeToString(raw),
		SignatureB64: base64.StdEncoding.EncodeToString(signature),
		Digest:       sourceDigest,
	}
}

// NewReadOnlyEvidenceHandler exports ONLY pre-existing, source-verified
// original AgentD signed history. The TLS listener MUST independently require
// and verify a client cert against the configured trust root (e.g. a TLS
// server with tls.RequireAndVerifyClientCert); the handler additionally checks
// a single exact scoped peer SPIFFE SAN and verified chain.
//
// A good Run-scoped certificate is necessary but not evidence of Guard Permit
// validity or right to dispatch. A trusted Head lookup must be injected from a
// different authority. There is no production issuer/PEP/writer permission,
// and an HTTP read cannot create Inspect events or cause resource release.
func NewReadOnlyEvidenceHandler(db *pgxpool.Pool, sourcePublicKey ed25519.PublicKey,
	trustDomain string, lookup PinnedHeadLookup) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path != EvidenceReadPath || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 ||
			len(r.TLS.PeerCertificates) == 0 ||
			len(r.TLS.PeerCertificates[0].URIs) != 1 {
			http.Error(w, "mTLS identity required", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		req, status := decodeReadRequest(r)
		if status != 0 {
			http.Error(w, "invalid evidence request", status)
			return
		}
		if !tlsPeerMatchesOriginal(r, req.Ref, trustDomain) {
			http.Error(w, "scope denied", http.StatusForbidden)
			return
		}
		if db == nil || len(sourcePublicKey) != ed25519.PublicKeySize || lookup == nil {
			http.Error(w, "source evidence unavailable", http.StatusServiceUnavailable)
			return
		}
		tx, err := db.BeginTx(r.Context(), pgx.TxOptions{
			IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
		})
		if err != nil {
			http.Error(w, "source evidence unavailable", http.StatusServiceUnavailable)
			return
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := verifyEvidenceReaderLogin(r.Context(), tx, req.Ref.TenantID); err != nil {
			http.Error(w, "source evidence reader identity denied", http.StatusServiceUnavailable)
			return
		}
		trustedHead, err := lookup(r.Context(), req.Ref)
		if err != nil || trustedHead.InspectCount == 0 ||
			trustedHead.JournalVersion != trustedHead.InspectCount ||
			len(trustedHead.Digest) != len("sha256:")+64 {
			http.Error(w, "independent source head unavailable", http.StatusServiceUnavailable)
			return
		}
		now := time.Now().UTC()
		history, err := loadInspectChainTx(r.Context(), tx, req.Ref,
			sourcePublicKey, now)
		if err != nil || len(history) == 0 {
			http.Error(w, "original source history unavailable", http.StatusConflict)
			return
		}
		if len(history) > maxExportedEvents || VerifyInspectAtHead(
			history, req.Ref, sourcePublicKey, now, trustedHead) != nil {
			// No pagination proof exists yet. A valid but too-long stream is
			// not an excuse to export an incomplete prefix as authoritative.
			http.Error(w, "source head mismatch or export bound reached", http.StatusConflict)
			return
		}
		last := history[len(history)-1]
		terminal, err := inspectCommandTx(r.Context(), tx, req.Ref, sourcePublicKey)
		if err != nil || terminal.State != last.Event.State ||
			terminal.ExitReceiptDigest != last.Event.ExitReceiptDigest ||
			terminal.NextAction != Hold || terminal.CanRetry ||
			terminal.CanDeclareReleased {
			http.Error(w, "original Wait source proof unavailable", http.StatusConflict)
			return
		}
		response := EvidenceReadResponse{
			Schema: EvidenceReadSchema, Ref: req.Ref,
			State: last.Event.State, NextAction: Hold,
			Head: trustedHead, Inspections: make([]SignedSourceRecord, 0, len(history)),
			CanRetry: false,
		}
		for _, item := range history {
			response.Inspections = append(response.Inspections,
				signedSource(item.Payload, item.Signature, item.Digest))
		}
		switch last.Event.State {
		case Unknown:
			if last.Event.ExitReceiptDigest != "" || len(terminal.ReceiptPayload) != 0 {
				http.Error(w, "unresolved source state", http.StatusConflict)
				return
			}
		case Exited, FailedConfirmed:
			if len(terminal.ReceiptPayload) == 0 {
				http.Error(w, "original Wait source proof unavailable", http.StatusConflict)
				return
			}
			proof := signedSource(terminal.ReceiptPayload,
				terminal.ReceiptSignature, terminal.ExitReceiptDigest)
			response.Terminal = &proof
		default:
			http.Error(w, "unknown original source inspection state", http.StatusConflict)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			http.Error(w, "source evidence snapshot unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// A truncated HTTP response cannot validate as a complete signed
		// evidence envelope on the independently verifying client.
		_ = json.NewEncoder(w).Encode(response)
	})
}
