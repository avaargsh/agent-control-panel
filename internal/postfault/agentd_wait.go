package postfault

import (
	"crypto/ed25519"
	"time"
)

// AgentDWaitRef mirrors ONLY the signed, immutable AgentD OS attempt identity.
// The separate Sandbox-owned module remains the sole authoritative writer.
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

// ExpectedAgentDWait must come from ACP's accepted Run and independent Guard
// binding, never from the candidate terminal payload or the LLM.
type ExpectedAgentDWait struct {
	Ref              AgentDWaitRef
	GuardOperationID string
}

const AgentDWaitDomain = "acp.agentd-wait-terminal/v1\x00"
const AgentDWaitSchema = "acp.agentd-wait-terminal/v1"

// VerifyWithAgentDWait will require a genuine owner-signed OS Wait terminal
// alongside the postfault signed G05 bundle. This stub is TDD RED only.
func VerifyWithAgentDWait(b Bundle, keys map[string]ed25519.PublicKey, expected ExpectedAgentDWait,
	terminalRaw, terminalSignature []byte, agentdSourceKey ed25519.PublicKey, now time.Time) error {
	return Verify(b, keys, now)
}
