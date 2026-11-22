package agentd

import (
	"context"
	"crypto/ed25519"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

const EvidenceReadPath = "/v1/agentd/evidence:read"
const EvidenceReadSchema = "acp.agentd-evidence-export/v1"

// PinnedHeadLookup MUST independently obtain a trusted exact Head from an
// authorized ACP evidence consumer, not from caller-supplied JSON or the
// candidate source journal itself.
type PinnedHeadLookup func(ctx context.Context, expected Ref) (InspectHead, error)

type EvidenceReadRequest struct {
	Ref Ref `json:"ref"`
}

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

// NewReadOnlyEvidenceHandler is ONLY a source read boundary; it cannot mint
// AgentD Inspect events, dispatch commands, issue Permits, or release leases.
// TDD scaffold: all access currently denied until authenticated tests pass.
func NewReadOnlyEvidenceHandler(db *pgxpool.Pool, sourcePublicKey ed25519.PublicKey,
	trustDomain string, lookup PinnedHeadLookup) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "evidence export unavailable", http.StatusForbidden)
	})
}
