package postfault

import (
	"crypto/ed25519"
	"time"
)

const AgentDInspectDomain = "acp.agentd-inspect-event/v1\x00"
const AgentDInspectSchema = "acp.agentd-inspect-event/v1"

type AgentDInspectEvent struct {
	Schema            string        `json:"schema"`
	Source            string        `json:"source"`
	Ref               AgentDWaitRef `json:"ref"`
	ObservedAt        string        `json:"observed_at"`
	InspectCount      uint64        `json:"inspect_count"`
	JournalVersion    uint64        `json:"journal_version"`
	PreviousDigest    string        `json:"previous_digest"`
	State             string        `json:"state"`
	ExitReceiptDigest string        `json:"exit_receipt_digest,omitempty"`
	NextAction        string        `json:"next_action"`
	DispatchCount     uint64        `json:"dispatch_count"`
	Replayed          bool          `json:"replayed"`
}

type SignedAgentDInspect struct {
	Payload   []byte
	Signature []byte
}

type TrustedAgentDInspectHead struct {
	InspectCount   uint64
	JournalVersion uint64
	Digest         string
}

// VerifyWithAgentDSourceJournal is an opt-in, read-only future G05 gate.
// This initial stub deliberately checks the OS Wait only, for behavior RED.
func VerifyWithAgentDSourceJournal(b Bundle, keys map[string]ed25519.PublicKey,
	expected ExpectedAgentDWait, waitRaw, waitSig []byte,
	source []SignedAgentDInspect, trustedHead TrustedAgentDInspectHead, now time.Time) error {
	return VerifyWithAgentDWait(b, keys, expected, waitRaw, waitSig, keys["agentd"], now)
}
