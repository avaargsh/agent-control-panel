package postfault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	AgentDInspectDomain = "acp.agentd-inspect-event/v1\x00"
	AgentDInspectSchema = "acp.agentd-inspect-event/v1"
)

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

// This head MUST be pinned by an independent source/consumer, not derived
// from the submitted inspect stream or an untrusted model-generated object.
type TrustedAgentDInspectHead struct {
	InspectCount   uint64
	JournalVersion uint64
	Digest         string
}

func inspectSourceDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", sum)
}

func strictSourceInspect(raw []byte, dst *AgentDInspectEvent) bool {
	if len(raw) == 0 || len(raw) > maxObservationSize || !StrictDecode(raw, dst) {
		return false
	}
	canon, err := json.Marshal(dst)
	return err == nil && bytes.Equal(raw, canon)
}

func findG05AgentDPhases(b Bundle) (Observation, Observation, error) {
	var before, after Observation
	var foundBefore, foundAfter bool
	for _, receipt := range b.Receipts {
		if receipt.Authority != "agentd" {
			continue
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(receipt.PayloadB64)
		if err != nil {
			return before, after, failure("invalid signed AgentD phase envelope")
		}
		var o Observation
		if !StrictDecode(raw, &o) || o.Command == nil {
			return before, after, failure("invalid signed AgentD source phase")
		}
		switch receipt.Phase {
		case "before_fault":
			before, foundBefore = o, true
		case "after_recovery":
			after, foundAfter = o, true
		}
	}
	if !foundBefore || !foundAfter {
		return before, after, failure("missing signed AgentD source phase")
	}
	return before, after, nil
}

// VerifyWithAgentDSourceJournal is an optional READ-ONLY additional G05
// consistency gate. It never manufactures Inspects or Wait receipts.
// It verifies the complete signed original AgentD inspect chain from count
// 1 through an independently pinned terminal Head, and joins pre/postfault
// source counts and terminal digest to a validated original same-Run Wait.
//
// A correct test fixture is NOT evidence of the actual Guard executor PEP,
// source mTLS identity, provider effect or physical compute resource release.
func VerifyWithAgentDSourceJournal(b Bundle, keys map[string]ed25519.PublicKey,
	expected ExpectedAgentDWait, waitRaw, waitSig []byte,
	source []SignedAgentDInspect, trustedHead TrustedAgentDInspectHead, now time.Time) error {
	if err := VerifyWithAgentDWait(b, keys, expected, waitRaw, waitSig, keys["agentd"], now); err != nil {
		return err
	}
	key := keys["agentd"]
	if len(key) != ed25519.PublicKeySize || len(source) < 2 || len(source) > 10000 ||
		trustedHead.InspectCount == 0 || !validDigest(trustedHead.Digest) {
		return failure("missing complete signed AgentD Inspect history or trusted Head")
	}
	phBefore, phAfter, err := findG05AgentDPhases(b)
	if err != nil {
		return err
	}
	var wait AgentDWaitStatement
	if !StrictDecode(waitRaw, &wait) {
		return failure("missing original AgentD Wait timestamp")
	}
	waitAt, err := time.Parse(time.RFC3339Nano, wait.ObservedAt)
	if err != nil {
		return failure("invalid original AgentD Wait time")
	}
	prevDigest := ""
	var prevTime time.Time
	var beforeFault AgentDInspectEvent
	var last AgentDInspectEvent
	var observedBefore bool
	var terminalObserved bool
	for i, envelope := range source {
		var event AgentDInspectEvent
		if len(envelope.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(key, append([]byte(AgentDInspectDomain), envelope.Payload...), envelope.Signature) ||
			!strictSourceInspect(envelope.Payload, &event) ||
			event.Schema != AgentDInspectSchema || event.Source != "agentd.inspect" ||
			event.Ref != expected.Ref || event.InspectCount != uint64(i+1) ||
			event.JournalVersion != event.InspectCount ||
			event.PreviousDigest != prevDigest || event.NextAction != "HOLD" ||
			event.DispatchCount != 1 || event.Replayed {
			return failure("AgentD source Inspect chain signature, order or original attempt invalid")
		}
		at, parseErr := time.Parse(time.RFC3339Nano, event.ObservedAt)
		if parseErr != nil || at.After(now) || (!prevTime.IsZero() && at.Before(prevTime)) {
			return failure("AgentD source inspection time invalid or regressed")
		}
		switch event.State {
		case "UNKNOWN":
			if event.ExitReceiptDigest != "" || terminalObserved {
				return failure("unresolved or retrograde AgentD terminal claim")
			}
		case "EXITED", "FAILED_CONFIRMED":
			if event.State != wait.Status || event.ExitReceiptDigest != inspectSourceDigest(waitRaw) ||
				at.Before(waitAt) {
				return failure("AgentD source Inspect terminal not linked to committed original Wait")
			}
			terminalObserved = true
		default:
			return failure("AgentD source Inspect state unknown or forged")
		}
		if at.Before(b.Fault.At) {
			if terminalObserved {
				return failure("source terminal predates claimed fault")
			}
			beforeFault = event
			observedBefore = true
		} else if !at.After(b.Fault.At) {
			return failure("ambiguous AgentD Inspect event at fault boundary")
		}
		last = event
		prevTime = at
		prevDigest = inspectSourceDigest(envelope.Payload)
	}
	if !observedBefore || !terminalObserved || !prevTime.After(b.Fault.At) ||
		last.State != wait.Status || last.ExitReceiptDigest != inspectSourceDigest(waitRaw) ||
		trustedHead.InspectCount != last.InspectCount ||
		trustedHead.JournalVersion != last.JournalVersion ||
		trustedHead.Digest != prevDigest {
		return failure("G05 requires complete AgentD source recovery Inspect and trusted exact Head")
	}
	if phBefore.Command.InspectCount != beforeFault.InspectCount ||
		phBefore.Command.JournalVersion != beforeFault.JournalVersion ||
		phBefore.Command.State != beforeFault.State ||
		phBefore.Command.CommandID != expected.Ref.CommandID ||
		phBefore.Command.AttemptID != expected.Ref.AttemptID ||
		phBefore.Command.ProviderCommandUID != expected.Ref.ProviderCommandUID ||
		phBefore.ObservedAt.Before(timeFromEvent(beforeFault)) ||
		phAfter.Command.InspectCount != last.InspectCount ||
		phAfter.Command.JournalVersion != last.JournalVersion ||
		phAfter.Command.State != last.State ||
		phAfter.Command.ExitReceiptDigest != last.ExitReceiptDigest ||
		phAfter.ObservedAt.Before(prevTime) {
		return failure("signed G05 AgentD observation does not match real source Inspect heads")
	}
	return nil
}

func timeFromEvent(event AgentDInspectEvent) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, event.ObservedAt)
	return t
}
