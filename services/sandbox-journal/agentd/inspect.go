// Package agentd owns the candidate read-only InspectCommand contract for
// one original, externally authorized AgentD attempt. No dispatch entrypoint
// exists here; Guard Permit issuer/PEP and authenticated principal are missing.
package agentd

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound   = errors.New("agentd original command attempt unavailable")
	ErrMismatch   = errors.New("agentd original attempt identity mismatch")
	ErrUnverified = errors.New("agentd terminal source proof unavailable or invalid")
	ErrNotReady   = errors.New("agentd authoritative inspect not yet implemented")
)

const (
	Unknown         = "UNKNOWN"
	Exited          = "EXITED"
	FailedConfirmed = "FAILED_CONFIRMED"
	Hold            = "HOLD"
	TerminalDomain  = "acp.agentd-wait-terminal/v1\x00"
	TerminalSchema  = "acp.agentd-wait-terminal/v1"
)

// Ref includes the original immutable Run, provider process identity and Guard
// reference, all pinned by the source-owned Journal. It is NOT a Permit.
type Ref struct {
	TenantID          string `json:"tenant_id"`
	RunID             string `json:"run_id"`
	RuntimeAttemptID  string `json:"runtime_attempt_id"`
	SandboxUID        string `json:"sandbox_uid"`
	CommandID         string `json:"command_id"`
	AttemptID         string `json:"attempt_id"`
	ProviderCommandUID string `json:"provider_command_uid"`
	RequestDigest     string `json:"request_digest"`
	GuardPermitID     string `json:"guard_permit_id"`
	PermitEpoch       uint64 `json:"permit_epoch"`
	ProcessPID        int    `json:"process_pid"`
	ProcessStartTicks uint64 `json:"process_start_ticks"`
	HostBootID        string `json:"host_boot_id"`
}

// TerminalReceipt must come from the AgentD process supervisor's actual OS
// Wait result and a durable atomic source commit. It is not synthesized by an
// inspecting client from pid absence, exit guesses or an ACK timeout.
type TerminalReceipt struct {
	Schema          string `json:"schema"`
	Source          string `json:"source"`
	Ref             Ref    `json:"ref"`
	ObservedAt      string `json:"observed_at"`
	Status          string `json:"status"`
	ExitCode        int    `json:"exit_code"`
	Signal          int    `json:"signal"`
	JournalRevision uint64 `json:"journal_revision"`
}

// Result never confers Guard authorization to release a resource. UNKNOWN
// means no authoritative persisted terminal outcome, even if PID disappeared.
type Result struct {
	Ref                Ref
	State              string
	NextAction         string
	OriginalProcess    string
	ExitReceiptDigest  string
	ReceiptPayload     []byte
	ReceiptSignature   []byte
	CanRetry           bool
	CanDeclareReleased bool
}

// InspectCommand MUST only trust the original attempt and an AgentD-signed,
// committed Wait receipt from the Sandbox-owned independent PostgreSQL DB.
func InspectCommand(ctx context.Context, db *pgxpool.Pool, expected Ref, trusted ed25519.PublicKey) (Result, error) {
	return Result{Ref: expected, State: Unknown, NextAction: Hold}, nil
}

// RecordWaitOutcome is for the source-owned AgentD supervisor that performed
// Wait on the originally registered process, never a remote status proposal.
func RecordWaitOutcome(ctx context.Context, db *pgxpool.Pool, original Ref, state *os.ProcessState, signer ed25519.PrivateKey) (TerminalReceipt, error) {
	return TerminalReceipt{}, ErrNotReady
}

// CaptureLinuxProcessIdentity obtains exact boot ID and Linux /proc starttime
// for an already-running OS process. The optional live probe MUST NOT turn
// absence of PID into evidence that an external operation failed.
func CaptureLinuxProcessIdentity(pid int) (string, uint64, error) {
	return "", 0, ErrNotReady
}
