package agentd

import (
	"context"
	"crypto/ed25519"
	"errors"
	"syscall"
	"testing"
	"time"
)

// A SIGKILLed child is reaped by the authoritative supervisor's actual OS
// Wait, but ProcessState.Exited is false on Linux for signaled termination.
// Unlike an absent Wait (which must remain UNKNOWN/HOLD), a *committed*
// signed Wait for this original attempt must be FAILED_CONFIRMED/HOLD.
func TestOriginalSIGKILLWaitCommitsSignedTerminalWithoutRedispatch(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	seedAlreadyAuthorizedAttempt(t, db, ref)
	public, private := testSourceInspectKey(t)

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("expected killed original child to return a nonzero Wait error")
	}
	if cmd.ProcessState == nil || cmd.ProcessState.Pid() != ref.ProcessPID {
		t.Fatal("no original child OS Wait state")
	}
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL ||
		cmd.ProcessState.Exited() || cmd.ProcessState.ExitCode() != -1 {
		t.Fatalf("test lacks a genuine Linux signaled OS Wait: status=%v state=%+v", ws, cmd.ProcessState)
	}
	// Before the source writes its independently signed OS Wait, inspecting
	// the missing PID must not infer termination or grant any retry.
	prior, err := InspectCommand(context.Background(), db, ref, public)
	if err != nil || prior.State != Unknown || prior.NextAction != Hold || prior.CanRetry ||
		prior.CanDeclareReleased || prior.ExitReceiptDigest != "" {
		t.Fatalf("uncommitted SIGKILL was promoted to a terminal: %+v %v", prior, err)
	}

	terminal, err := RecordWaitOutcome(context.Background(), db, ref, cmd.ProcessState, private)
	if err != nil || terminal.Status != FailedConfirmed || terminal.Signal != int(syscall.SIGKILL) ||
		terminal.ExitCode != -1 {
		t.Fatalf("real SIGKILL OS Wait could not be committed as source fact: %+v %v", terminal, err)
	}
	// A duplicate ACK cannot mint a second terminal or change the first.
	replayed, err := RecordWaitOutcome(context.Background(), db, ref, cmd.ProcessState, private)
	if err != nil || terminal != replayed {
		t.Fatalf("duplicate original OS Wait did not reuse immutable terminal: %+v %+v %v", terminal, replayed, err)
	}
	got, err := InspectCommand(context.Background(), db, ref, public)
	if err != nil || got.State != FailedConfirmed || got.NextAction != Hold || got.CanRetry ||
		got.CanDeclareReleased || got.ExitReceiptDigest == "" ||
		!ed25519.Verify(public, append([]byte(TerminalDomain), got.ReceiptPayload...), got.ReceiptSignature) {
		t.Fatalf("original SIGKILL signed Wait not independently inspectable: %+v %v", got, err)
	}
	ev, err := InspectAndJournal(context.Background(), db, ref, public, private)
	if err != nil || ev.Event.State != FailedConfirmed ||
		ev.Event.ExitReceiptDigest != got.ExitReceiptDigest || ev.Result.CanRetry ||
		ev.Result.CanDeclareReleased || ev.Event.InspectCount != 1 {
		t.Fatalf("original SIGKILL terminal not reflected in signed Inspect event: %+v %v", ev, err)
	}
	if err := VerifyInspectChain([]JournaledInspection{ev}, ref, public, time.Now().UTC()); err != nil {
		t.Fatalf("source-signed SIGKILL inspection chain unverifiable: %v", err)
	}

	var count int
	if err := db.QueryRow(context.Background(),
		"SELECT count(*) FROM public.sandbox_agentd_terminal_receipts WHERE tenant_id=$1 AND command_id=$2 AND attempt_id=$3",
		ref.TenantID, ref.CommandID, ref.AttemptID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("original SIGKILL Wait was not persisted exactly once: count=%d err=%v", count, err)
	}
	if errors.Is(err, ErrUnverified) {
		t.Fatal("unverified source Wait")
	}
}
