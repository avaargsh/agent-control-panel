package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/postfault"
)

const (
	headAcceptanceSchema   = "acp.g05-head-acceptance/v1"
	headAcceptanceDomain   = "acp.g05-head-acceptance/v1\x00"
	maxHeadAcceptanceBytes = 8192
)

// headAcceptanceEnvelope transports the original signed bytes without
// reserializing them before Ed25519 verification. It is NOT created or signed
// by the postfault CLI, AgentD HTTP export, or any model input.
type headAcceptanceEnvelope struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
}

// headAcceptanceStatement describes what a separately authorized ACP/Guard-
// aware Head acceptance source attested, not what AgentD itself claims. A
// separate authenticated publisher and durable anti-rollback ledger do NOT
// exist in this Draft; the verifier refuses unsigned or altered claims but
// cannot establish that this is the latest acceptance revision.
type headAcceptanceStatement struct {
	Schema     string          `json:"schema"`
	Binding    expectedBinding `json:"binding"`
	Revision   uint64          `json:"revision"`
	AcceptedAt time.Time       `json:"accepted_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
}

var errHeadAcceptance = errors.New("independent signed AgentD Head acceptance unavailable or untrusted")

// verifyHeadAcceptance is an additional fail-closed preflight executed before
// contacting AgentD. The signed statement must cover the COMPLETE original
// same-Run/fault/Guard Operation/Permit/Attempt and exact Inspect Head.
//
// The independent public key is out-of-band operator configuration and MUST
// be different from each Runtime/Sandbox/AgentD/Guard source signing key.
// A valid signature alone is NOT proof of current monotonic Head freshness.
func verifyHeadAcceptance(raw []byte, expected expectedBinding,
	acceptor ed25519.PublicKey, sourceKeys map[string]ed25519.PublicKey,
	now time.Time) error {
	if len(raw) == 0 || len(raw) > maxHeadAcceptanceBytes ||
		len(acceptor) != ed25519.PublicKeySize ||
		len(sourceKeys["agentd"]) != ed25519.PublicKeySize ||
		now.IsZero() || expected.AgentDRef == nil || expected.AgentDHead == nil {
		return errHeadAcceptance
	}
	for _, key := range sourceKeys {
		if len(key) != ed25519.PublicKeySize || bytes.Equal(key, acceptor) {
			return errHeadAcceptance
		}
	}
	var envelope headAcceptanceEnvelope
	if !postfault.StrictDecode(bytes.TrimSpace(raw), &envelope) {
		return errHeadAcceptance
	}
	canonicalEnvelope, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonicalEnvelope) {
		return errHeadAcceptance
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.PayloadB64)
	if err != nil || len(payload) == 0 || len(payload) > maxHeadAcceptanceBytes {
		return errHeadAcceptance
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(acceptor, append([]byte(headAcceptanceDomain), payload...), signature) {
		return errHeadAcceptance
	}
	var accepted headAcceptanceStatement
	if !postfault.StrictDecode(payload, &accepted) {
		return errHeadAcceptance
	}
	canonicalPayload, err := json.Marshal(accepted)
	if err != nil || !bytes.Equal(payload, canonicalPayload) ||
		accepted.Schema != headAcceptanceSchema ||
		accepted.Binding.Schema != expectedBindingVersion ||
		accepted.Revision == 0 || !reflect.DeepEqual(accepted.Binding, expected) ||
		expected.AgentDRef.TenantID != expected.Subject.TenantID ||
		expected.AgentDRef.RunID != expected.Subject.RunID ||
		expected.AgentDGuardOperationID != expected.Subject.GuardOperationID ||
		expected.AgentDHead.InspectCount == 0 ||
		expected.AgentDHead.JournalVersion != expected.AgentDHead.InspectCount ||
		accepted.AcceptedAt.IsZero() || accepted.ExpiresAt.IsZero() ||
		accepted.AcceptedAt.Before(expected.FaultAt) ||
		accepted.AcceptedAt.After(now) || !accepted.ExpiresAt.After(now) ||
		!accepted.ExpiresAt.After(accepted.AcceptedAt) ||
		accepted.ExpiresAt.Sub(accepted.AcceptedAt) > 24*time.Hour {
		return errHeadAcceptance
	}
	return nil
}
