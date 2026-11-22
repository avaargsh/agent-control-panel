package postfault

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"time"
)

const AgentDEvidenceReadPath = "/v1/agentd/evidence:read"
const AgentDEvidenceReadSchema = "acp.agentd-evidence-export/v1"

type AgentDWireRecord struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
	Digest       string `json:"digest"`
}

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

// FetchAndVerifyAgentDEvidence consumes only the existing authenticated
// AgentD read endpoint. No dispatch, retry, Permit, settlement or release.
//
// Inputs MUST be independently pinned by ACP accepted Run / actual Guard
// Permit, source trust keys and a separately trusted Head. This is an
// intentionally failing TDD scaffold until the real TLS consumer is wired.
func FetchAndVerifyAgentDEvidence(ctx context.Context, endpoint string, credentials *tls.Config,
	b Bundle, keys map[string]ed25519.PublicKey, expected ExpectedAgentDWait,
	head TrustedAgentDInspectHead, now time.Time) error {
	return failure("authenticated original AgentD evidence consumer unavailable")
}
