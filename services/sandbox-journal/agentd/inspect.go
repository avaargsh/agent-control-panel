// Package agentd implements candidate source-owned, fail-closed inspection
// of one originally authorized external command. It does NOT dispatch a
// command, issue a Guard Permit, grant egress, or release Sandbox/Compute.
package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"syscall"
	"time"

	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound   = errors.New("agentd original command attempt unavailable")
	ErrMismatch   = errors.New("agentd original attempt identity mismatch")
	ErrUnverified = errors.New("agentd terminal source proof unavailable or invalid")
)

const (
	Unknown         = "UNKNOWN"
	Exited          = "EXITED"
	FailedConfirmed = "FAILED_CONFIRMED"
	Hold            = "HOLD"
	TerminalDomain  = "acp.agentd-wait-terminal/v1\x00"
	TerminalSchema  = "acp.agentd-wait-terminal/v1"
)

var sourceRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var bootIDRef = regexp.MustCompile(`^[0-9a-f-]{36}$`)

// Ref is an immutable attempt identity from the authoritative AgentD owner,
// NOT an authorization. Original process PID alone is insufficient: the host
// boot ID and Linux process start ticks fence PID reuse.
type Ref struct {
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

func (r Ref) valid() bool {
	return identity.Intent{
		TenantID: r.TenantID, RunID: r.RunID, RuntimeAttemptID: r.RuntimeAttemptID,
		SandboxUID: r.SandboxUID, CommandID: r.CommandID, RequestDigest: r.RequestDigest,
	}.Validate() == nil &&
		sourceRef.MatchString(r.AttemptID) && sourceRef.MatchString(r.ProviderCommandUID) &&
		sourceRef.MatchString(r.GuardPermitID) && bootIDRef.MatchString(r.HostBootID) &&
		r.PermitEpoch > 0 && r.PermitEpoch <= 1<<63-1 &&
		r.ProcessPID > 0 && r.ProcessStartTicks > 0 && r.ProcessStartTicks <= 1<<63-1
}

// TerminalReceipt contains only the actual source supervisor's OS Wait facts,
// never status submitted by the inspecting client. The original signed bytes
// are stored atomically in the Sandbox-owned, append-only PostgreSQL journal.
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

func blocked(r Ref) Result {
	return Result{Ref: r, State: Unknown, NextAction: Hold}
}

func scanOriginal(row pgx.Row) (Ref, error) {
	var r Ref
	var permitEpoch, ticks int64
	err := row.Scan(
		&r.TenantID, &r.RunID, &r.RuntimeAttemptID,
		&r.SandboxUID, &r.CommandID, &r.AttemptID,
		&r.ProviderCommandUID, &r.RequestDigest, &r.GuardPermitID,
		&permitEpoch, &r.ProcessPID, &ticks, &r.HostBootID,
	)
	if err != nil {
		return Ref{}, err
	}
	if permitEpoch <= 0 || ticks <= 0 {
		return Ref{}, ErrUnverified
	}
	r.PermitEpoch, r.ProcessStartTicks = uint64(permitEpoch), uint64(ticks)
	if !r.valid() {
		return Ref{}, ErrUnverified
	}
	return r, nil
}

const selectOriginal = `SELECT tenant_id,run_id,runtime_attempt_id,sandbox_uid,command_id,
	attempt_id,provider_command_uid,request_digest,guard_permit_id,permit_epoch,
	process_pid,process_start_ticks,host_boot_id
	FROM public.sandbox_agentd_attempts
	WHERE tenant_id=$1 AND sandbox_uid=$2 AND command_id=$3 AND attempt_id=$4`

func readOriginal(ctx context.Context, tx pgx.Tx, expected Ref) error {
	got, err := scanOriginal(tx.QueryRow(ctx, selectOriginal,
		expected.TenantID, expected.SandboxUID, expected.CommandID, expected.AttemptID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return ErrUnverified
	}
	if got != expected {
		return ErrMismatch
	}
	return nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", sum)
}

// verifyTerminal checks the exact signed bytes, complete original immutable
// identity and unambiguous source status. No JSON normalization is allowed
// before signature verification or digest comparison.
func verifyTerminal(raw, signature []byte, storedDigest string, original Ref, trusted ed25519.PublicKey) (TerminalReceipt, error) {
	var terminal TerminalReceipt
	if len(raw) == 0 || len(raw) > 8192 || len(trusted) != ed25519.PublicKeySize ||
		len(signature) != ed25519.SignatureSize || digest(raw) != storedDigest ||
		!ed25519.Verify(trusted, append([]byte(TerminalDomain), raw...), signature) {
		return terminal, ErrUnverified
	}
	if err := json.Unmarshal(raw, &terminal); err != nil {
		return terminal, ErrUnverified
	}
	canonical, err := json.Marshal(terminal)
	if err != nil || !bytes.Equal(canonical, raw) ||
		terminal.Schema != TerminalSchema || terminal.Source != "agentd.os.wait" ||
		terminal.Ref != original || terminal.JournalRevision != 2 ||
		terminal.ObservedAt == "" {
		return TerminalReceipt{}, ErrUnverified
	}
	tm, err := time.Parse(time.RFC3339Nano, terminal.ObservedAt)
	if err != nil || tm.After(time.Now().UTC().Add(10*time.Second)) {
		return TerminalReceipt{}, ErrUnverified
	}
	if terminal.Status != Exited && terminal.Status != FailedConfirmed {
		return TerminalReceipt{}, ErrUnverified
	}
	if (terminal.Status == Exited) != (terminal.ExitCode == 0 && terminal.Signal == 0) {
		return TerminalReceipt{}, ErrUnverified
	}
	if terminal.Signal < 0 || terminal.Signal > 128 ||
		(terminal.Signal != 0 && terminal.ExitCode != -1) {
		return TerminalReceipt{}, ErrUnverified
	}
	return terminal, nil
}

// InspectCommand queries original process + source journal in one
// repeatable-read snapshot. An absent PID or a lost ACK is NEVER a terminal
// receipt. A committed, independently signed AgentD Wait is the ONLY path
// to EXITED/FAILED_CONFIRMED. No re-dispatch or resource-release action exists.
func InspectCommand(ctx context.Context, db *pgxpool.Pool, expected Ref, trusted ed25519.PublicKey) (Result, error) {
	hold := blocked(expected)
	if db == nil || !expected.valid() || len(trusted) != ed25519.PublicKeySize {
		return hold, ErrUnverified
	}
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return hold, ErrUnverified
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := readOriginal(ctx, tx, expected); err != nil {
		return hold, err
	}
	var raw, signature []byte
	var savedDigest string
	err = tx.QueryRow(ctx, `SELECT payload,signature,payload_digest
		FROM public.sandbox_agentd_terminal_receipts
		WHERE tenant_id=$1 AND sandbox_uid=$2 AND command_id=$3 AND attempt_id=$4`,
		expected.TenantID, expected.SandboxUID, expected.CommandID, expected.AttemptID,
	).Scan(&raw, &signature, &savedDigest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return hold, ErrUnverified
	}
	if err == nil {
		terminal, verifyErr := verifyTerminal(raw, signature, savedDigest, expected, trusted)
		if verifyErr != nil {
			return hold, verifyErr
		}
		hold.State = terminal.Status
		hold.ExitReceiptDigest = savedDigest
		hold.ReceiptPayload = raw
		hold.ReceiptSignature = signature
	}
	if err := tx.Commit(ctx); err != nil {
		return blocked(expected), ErrUnverified
	}
	hold.OriginalProcess = inspectLinuxOriginalProcess(expected)
	// A confirmed terminal permits external *independent* lifecycle checks,
	// but not blindly retrying or releasing a Guard/Compute lease.
	return hold, nil
}

// RecordWaitOutcome may ONLY be called in the trusted AgentD supervisor with
// a real os.ProcessState obtained from Wait of the ORIGINAL started process.
// The source-owned Journal must have been created by an independently
// authorized Guard PEP path; this candidate does not implement registration.
func RecordWaitOutcome(ctx context.Context, db *pgxpool.Pool, original Ref, state *os.ProcessState, signer ed25519.PrivateKey) (TerminalReceipt, error) {
	if db == nil || !original.valid() || state == nil || !state.Exited() ||
		state.Pid() != original.ProcessPID || len(signer) != ed25519.PrivateKeySize {
		return TerminalReceipt{}, ErrUnverified
	}
	signal := 0
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		signal = int(ws.Signal())
	}
	code := state.ExitCode()
	status := FailedConfirmed
	if code == 0 && signal == 0 {
		status = Exited
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return TerminalReceipt{}, ErrUnverified
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := readOriginal(ctx, tx, original); err != nil {
		return TerminalReceipt{}, err
	}
	terminal := TerminalReceipt{
		Schema: TerminalSchema, Source: "agentd.os.wait",
		Ref: original, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Status: status, ExitCode: code, Signal: signal, JournalRevision: 2,
	}
	raw, err := json.Marshal(terminal)
	if err != nil {
		return TerminalReceipt{}, ErrUnverified
	}
	signed := ed25519.Sign(signer, append([]byte(TerminalDomain), raw...))
	_, err = tx.Exec(ctx, `INSERT INTO public.sandbox_agentd_terminal_receipts
		(tenant_id,sandbox_uid,command_id,attempt_id,payload,signature,payload_digest)
		VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
		original.TenantID, original.SandboxUID, original.CommandID, original.AttemptID,
		raw, signed, digest(raw))
	if err != nil {
		return TerminalReceipt{}, ErrUnverified
	}
	// ACK loss or concurrent duplicate waiter can only re-read the FIRST
	// immutable signed receipt, not replace it or insert a second event.
	var committedPayload, committedSignature []byte
	var savedDigest string
	if err := tx.QueryRow(ctx, `SELECT payload,signature,payload_digest
		FROM public.sandbox_agentd_terminal_receipts
		WHERE tenant_id=$1 AND sandbox_uid=$2 AND command_id=$3 AND attempt_id=$4`,
		original.TenantID, original.SandboxUID, original.CommandID, original.AttemptID).
		Scan(&committedPayload, &committedSignature, &savedDigest); err != nil {
		return TerminalReceipt{}, ErrUnverified
	}
	committed, err := verifyTerminal(committedPayload, committedSignature, savedDigest,
		original, signer.Public().(ed25519.PublicKey))
	if err != nil || committed.Status != status || committed.ExitCode != code || committed.Signal != signal {
		return TerminalReceipt{}, ErrUnverified
	}
	if err := tx.Commit(ctx); err != nil {
		return TerminalReceipt{}, ErrUnverified
	}
	return committed, nil
}
