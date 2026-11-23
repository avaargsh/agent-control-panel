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

// AgentDWaitRef mirrors only AgentD's original signed OS attempt identity;
// the independent Sandbox-owned PostgreSQL source remains the sole writer.
type AgentDWaitRef struct {
	TenantID           string `json:"tenant_id"`
	RunID              string `json:"run_id"`
	RuntimeAttemptID   string `json:"runtime_attempt_id"`
	SandboxUID         string `json:"sandbox_uid"`
	CommandID          string `json:"command_id"`
	AttemptID          string `json:"attempt_id"`
	ProviderCommandUID string `json:"provider_command_uid"`
	RequestDigest      string `json:"request_digest"`
	GuardPermitID      string `json:"guard_permit_id"`
	PermitEpoch        uint64 `json:"permit_epoch"`
	ProcessPID         int    `json:"process_pid"`
	ProcessStartTicks  uint64 `json:"process_start_ticks"`
	HostBootID         string `json:"host_boot_id"`
}

type AgentDWaitStatement struct {
	Schema          string        `json:"schema"`
	Source          string        `json:"source"`
	Ref             AgentDWaitRef `json:"ref"`
	ObservedAt      string        `json:"observed_at"`
	Status          string        `json:"status"`
	ExitCode        int           `json:"exit_code"`
	Signal          int           `json:"signal"`
	JournalRevision uint64        `json:"journal_revision"`
}

// ExpectedAgentDWait must be obtained from ACP's accepted Run and separately
// authenticated Guard, not copied from a candidate terminal or LLM response.
type ExpectedAgentDWait struct {
	Ref              AgentDWaitRef
	GuardOperationID string
}

const AgentDWaitDomain = "acp.agentd-wait-terminal/v1\x00"
const AgentDWaitSchema = "acp.agentd-wait-terminal/v1"

// VerifyWithAgentDWait adds source-owned, cryptographic OS Wait terminal
// verification to an already valid eight-observation G05 signed bundle.
// A correct-looking ExitReceiptDigest or signed postfault AgentD assertion
// is NOT enough: the exact original source Wait bytes must independently
// verify and bind to the same Run, Attempt, Provider, Permit and process.
//
// This is a necessary cross-service evidence join, not a command dispatcher,
// authenticated transport, proof of a durable fresh InspectCount, permission
// to release resources or a replacement for real Guard PEP/provider Inspect.
func VerifyWithAgentDWait(b Bundle, keys map[string]ed25519.PublicKey, expected ExpectedAgentDWait,
	terminalRaw, terminalSignature []byte, agentdSourceKey ed25519.PublicKey, now time.Time) error {
	if err := Verify(b, keys, now); err != nil {
		return err
	}
	if !validSubject(b.Subject) || expected.GuardOperationID != b.Subject.GuardOperationID ||
		expected.Ref.TenantID != b.Subject.TenantID || expected.Ref.RunID != b.Subject.RunID ||
		!safeID(expected.Ref.RuntimeAttemptID) || !safeID(expected.Ref.SandboxUID) ||
		!safeID(expected.Ref.CommandID) || !safeID(expected.Ref.AttemptID) ||
		!safeID(expected.Ref.ProviderCommandUID) || !safeID(expected.Ref.GuardPermitID) ||
		!safeID(expected.Ref.HostBootID) || !validDigest(expected.Ref.RequestDigest) ||
		expected.Ref.PermitEpoch == 0 || expected.Ref.ProcessPID <= 0 ||
		expected.Ref.ProcessStartTicks == 0 {
		return failure("missing independent original AgentD Run/Attempt/Guard binding")
	}
	if len(terminalRaw) == 0 || len(terminalRaw) > maxObservationSize ||
		len(terminalSignature) != ed25519.SignatureSize ||
		len(agentdSourceKey) != ed25519.PublicKeySize ||
		!bytes.Equal(agentdSourceKey, keys["agentd"]) ||
		!ed25519.Verify(agentdSourceKey, append([]byte(AgentDWaitDomain), terminalRaw...), terminalSignature) {
		return failure("invalid independent AgentD OS Wait signature or source key")
	}
	var terminal AgentDWaitStatement
	if !StrictDecode(terminalRaw, &terminal) {
		return failure("ambiguous or invalid original AgentD Wait statement")
	}
	canonical, err := json.Marshal(terminal)
	if err != nil || !bytes.Equal(terminalRaw, canonical) ||
		terminal.Schema != AgentDWaitSchema || terminal.Source != "agentd.os.wait" ||
		terminal.Ref != expected.Ref || terminal.JournalRevision != 2 {
		return failure("AgentD OS Wait source or original immutable attempt does not match")
	}
	observedAt, err := time.Parse(time.RFC3339Nano, terminal.ObservedAt)
	if err != nil || !observedAt.After(b.Fault.At) || observedAt.After(now) {
		return failure("AgentD Wait terminal outside genuine postfault window")
	}
	if terminal.Status != "EXITED" && terminal.Status != "FAILED_CONFIRMED" {
		return failure("AgentD source did not observe a terminal OS Wait")
	}
	if (terminal.Status == "EXITED") != (terminal.ExitCode == 0 && terminal.Signal == 0) ||
		terminal.Signal < 0 || terminal.Signal > 128 ||
		(terminal.Signal == 0 && (terminal.ExitCode < 0 || terminal.ExitCode > 255)) ||
		(terminal.Signal != 0 && terminal.ExitCode != -1) {
		return failure("AgentD terminal Wait exit/signal/status contradict one another")
	}
	// The original independently signed AgentD after-recovery and Guard
	// revalidation must commit to the same Wait and Permit. Never accept a
	// separate valid signature from a different command, lease or Run.
	var agentAfter, guardAfter Observation
	var foundAgent, foundGuard bool
	for _, receipt := range b.Receipts {
		if receipt.Phase != "after_recovery" ||
			(receipt.Authority != "agentd" && receipt.Authority != "guard") {
			continue
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(receipt.PayloadB64)
		if err != nil {
			return failure("invalid signed postfault authority bytes")
		}
		switch receipt.Authority {
		case "agentd":
			if !StrictDecode(raw, &agentAfter) {
				return failure("invalid signed AgentD Inspect observation")
			}
			foundAgent = true
		case "guard":
			if !StrictDecode(raw, &guardAfter) {
				return failure("invalid signed Guard revalidation observation")
			}
			foundGuard = true
		}
	}
	sum := sha256.Sum256(terminalRaw)
	digest := fmt.Sprintf("sha256:%x", sum)
	if !foundAgent || !foundGuard || agentAfter.Command == nil || guardAfter.Guard == nil ||
		agentAfter.Command.CommandID != terminal.Ref.CommandID ||
		agentAfter.Command.AttemptID != terminal.Ref.AttemptID ||
		agentAfter.Command.ProviderCommandUID != terminal.Ref.ProviderCommandUID ||
		agentAfter.Command.State != terminal.Status ||
		agentAfter.Command.ExitReceiptDigest != digest ||
		agentAfter.ObservedAt.Before(observedAt) ||
		guardAfter.Guard.PermitID != terminal.Ref.GuardPermitID ||
		guardAfter.Guard.PermitEpoch != terminal.Ref.PermitEpoch {
		return failure("G05 signed source Wait not linked to original AgentD Inspect and Guard Permit")
	}
	return nil
}
