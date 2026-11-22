package postfault

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func signedInspectSource(t *testing.T, event AgentDInspectEvent, private ed25519.PrivateKey) SignedAgentDInspect {
	t.Helper()
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return SignedAgentDInspect{
		Payload: raw, Signature: ed25519.Sign(private, append([]byte(AgentDInspectDomain), raw...)),
	}
}

func inspectDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", sum)
}

func g05SourceFixture(t *testing.T) (Bundle, map[string]ed25519.PublicKey, ExpectedAgentDWait,
	[]byte, []byte, []SignedAgentDInspect, TrustedAgentDInspectHead, time.Time, ed25519.PrivateKey) {
	t.Helper()
	b, keys, signers, expected, wait, now := waitSourceFixture(t)
	waitRaw, waitSig := signedWaitBytes(t, wait, signers["agentd"])
	bindG05ExitDigest(t, &b, signers, waitRaw)
	mutateReport(t, &b, signers, "agentd", "before_fault", func(o *Observation) {
		o.Command.JournalVersion = 1
		o.Command.InspectCount = 1
	})
	mutateReport(t, &b, signers, "agentd", "after_recovery", func(o *Observation) {
		o.Command.JournalVersion = 2
		o.Command.InspectCount = 2
	})
	before := AgentDInspectEvent{
		Schema: AgentDInspectSchema, Source: "agentd.inspect",
		Ref: wait.Ref, ObservedAt: b.Fault.At.Add(-2 * time.Second).Format(time.RFC3339Nano),
		InspectCount: 1, JournalVersion: 1,
		State: "UNKNOWN", NextAction: "HOLD", DispatchCount: 1,
	}
	first := signedInspectSource(t, before, signers["agentd"])
	after := before
	after.ObservedAt = b.Fault.At.Add(750 * time.Millisecond).Format(time.RFC3339Nano)
	after.InspectCount, after.JournalVersion = 2, 2
	after.PreviousDigest = inspectDigest(first.Payload)
	after.State = "EXITED"
	after.ExitReceiptDigest = inspectDigest(waitRaw)
	second := signedInspectSource(t, after, signers["agentd"])
	events := []SignedAgentDInspect{first, second}
	head := TrustedAgentDInspectHead{InspectCount: 2, JournalVersion: 2, Digest: inspectDigest(second.Payload)}
	if err := Verify(b, keys, now); err != nil {
		t.Fatalf("precondition: signed postfault bundle invalid: %v", err)
	}
	return b, keys, expected, waitRaw, waitSig, events, head, now, signers["agentd"]
}

func TestG05SourceAcceptsVerifiedOriginalWaitAndCompleteFreshInspectJournal(t *testing.T) {
	b, keys, expected, waitRaw, waitSig, events, head, now, _ := g05SourceFixture(t)
	if err := VerifyWithAgentDSourceJournal(b, keys, expected, waitRaw, waitSig, events, head, now); err != nil {
		t.Fatalf("complete independently signed original same-Run Inspect chain rejected: %v", err)
	}
}

func TestG05SourceRejectsTamperedSignedInspectChainOrReplayedHead(t *testing.T) {
	for _, name := range []string{
		"missing_chain", "prefix_rollback", "wrong_head", "reordered",
		"tampered_signature", "foreign_run_signed", "other_attempt_signed",
		"foreign_guard_signed", "stale_postfault_observation_signed",
		"forged_terminal_digest_signed", "replayed_count_signed",
		"broken_previous_digest_signed", "unresolved_unknown_signed",
	} {
		t.Run(name, func(t *testing.T) {
			b, keys, expected, waitRaw, waitSig, original, head, now, priv := g05SourceFixture(t)
			events := append([]SignedAgentDInspect(nil), original...)
			switch name {
			case "missing_chain":
				events = nil
			case "prefix_rollback":
				events = events[:1]
			case "wrong_head":
				head.Digest = "sha256:" + strings.Repeat("f", 64)
			case "reordered":
				events[0], events[1] = events[1], events[0]
			case "tampered_signature":
				events[1].Signature = make([]byte, ed25519.SignatureSize)
			default:
				var claim AgentDInspectEvent
				if err := json.Unmarshal(events[1].Payload, &claim); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "foreign_run_signed":
					claim.Ref.RunID = "another-run"
				case "other_attempt_signed":
					claim.Ref.AttemptID = "other-command-attempt"
				case "foreign_guard_signed":
					claim.Ref.GuardPermitID = "other-permit"
				case "stale_postfault_observation_signed":
					claim.ObservedAt = b.Fault.At.Add(-time.Second).Format(time.RFC3339Nano)
				case "forged_terminal_digest_signed":
					claim.ExitReceiptDigest = "sha256:" + strings.Repeat("f", 64)
				case "replayed_count_signed":
					claim.InspectCount = 1
				case "broken_previous_digest_signed":
					claim.PreviousDigest = "sha256:" + strings.Repeat("f", 64)
				case "unresolved_unknown_signed":
					claim.State = "UNKNOWN"
					claim.ExitReceiptDigest = ""
				}
				events[1] = signedInspectSource(t, claim, priv)
				if name != "broken_previous_digest_signed" && name != "foreign_run_signed" {
					// The head is pinned independently; the test re-signs
					// a forged event and pins the forged digest to ensure
					// rejection checks more than a mismatched HEAD hash.
					head.Digest = inspectDigest(events[1].Payload)
				}
			}
			if err := VerifyWithAgentDSourceJournal(b, keys, expected, waitRaw, waitSig, events, head, now); err == nil {
				t.Fatalf("G05 accepted invalid AgentD Inspect source: %s", name)
			}
		})
	}
}
