package agentd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SANDBOX_JOURNAL_TEST_DSN")
	if dsn == "" {
		t.Skip("requires independent real PostgreSQL in Sandbox-owned CI")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	raw, err := os.ReadFile(filepath.Join("..", "migrations", "0013_agentd_attempt_terminal.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), string(raw)); err != nil {
		t.Fatalf("owner-only AgentD migration: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		"TRUNCATE public.sandbox_agentd_terminal_receipts,public.sandbox_agentd_attempts"); err != nil {
		t.Fatal(err)
	}
	return pool
}

func startOwnedTestProcess(t *testing.T, duration string) (*exec.Cmd, Ref) {
	t.Helper()
	// Real OS child; only the disposable test owns this process. This is
	// NOT a Sandbox dispatch API or evidence of Guard authorization.
	cmd := exec.Command("/bin/sh", "-c", "sleep "+duration+"; exit 7")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	bootID, ticks, err := CaptureLinuxProcessIdentity(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	return cmd, Ref{
		TenantID: "agentd-tenant-a",
		RunID: "11111111-1111-4111-8111-111111111111",
		RuntimeAttemptID: "runtime-attempt-1",
		SandboxUID: "sandbox-uid-1", CommandID: "command-1",
		AttemptID: "executor-attempt-1",
		ProviderCommandUID: "provider-command-uid-1",
		RequestDigest: "sha256:" + strings.Repeat("a", 64),
		GuardPermitID: "guard-permit-1", PermitEpoch: 7,
		ProcessPID: cmd.Process.Pid, ProcessStartTicks: ticks, HostBootID: bootID,
	}
}

func seedAlreadyAuthorizedAttempt(t *testing.T, pool *pgxpool.Pool, ref Ref) {
	t.Helper()
	// Only a disposable PostgreSQL owner can seed this fixture. Production
	// has no writer grant and MUST require an independently verified Guard
	// issuer / executor PEP before adding an actual dispatched attempt.
	_, err := pool.Exec(context.Background(), `INSERT INTO public.sandbox_agentd_attempts
		(tenant_id,run_id,runtime_attempt_id,sandbox_uid,command_id,attempt_id,
		provider_command_uid,request_digest,guard_permit_id,permit_epoch,
		process_pid,process_start_ticks,host_boot_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		ref.TenantID, ref.RunID, ref.RuntimeAttemptID, ref.SandboxUID,
		ref.CommandID, ref.AttemptID, ref.ProviderCommandUID, ref.RequestDigest,
		ref.GuardPermitID, ref.PermitEpoch, ref.ProcessPID, ref.ProcessStartTicks, ref.HostBootID)
	if err != nil {
		t.Fatalf("seed original owner-only attempt: %v", err)
	}
}

func TestInspectMissingCommittedTerminalRemainsUnknownAndCannotRetry(t *testing.T) {
	pool := testDatabase(t)
	cmd, original := startOwnedTestProcess(t, "0.1")
	seedAlreadyAuthorizedAttempt(t, pool, original)
	_ = cmd.Wait() // Actual process disappeared; supervisor NEVER persisted Wait.
	trusted, _, _ := ed25519.GenerateKey(rand.Reader)
	got, err := InspectCommand(context.Background(), pool, original, trusted)
	if err != nil || got.State != Unknown || got.NextAction != Hold || got.CanRetry ||
		got.CanDeclareReleased || got.ExitReceiptDigest != "" {
		t.Fatalf("PID absence/lost Wait ACK promoted uncertain outcome: got=%+v err=%v", got, err)
	}
	var terminalCount int
	if err := pool.QueryRow(context.Background(),
		"SELECT count(*) FROM public.sandbox_agentd_terminal_receipts").Scan(&terminalCount); err != nil || terminalCount != 0 {
		t.Fatalf("inspection fabricated a terminal event: count=%d err=%v", terminalCount, err)
	}
}

func TestInspectWrongOriginalAttemptDoesNotExposeOrRebind(t *testing.T) {
	pool := testDatabase(t)
	cmd, original := startOwnedTestProcess(t, "0.2")
	seedAlreadyAuthorizedAttempt(t, pool, original)
	defer func() { _ = cmd.Wait() }()
	trusted, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, mutate := range []func(*Ref){
		func(r *Ref) { r.RunID = "22222222-2222-4222-8222-222222222222" },
		func(r *Ref) { r.TenantID = "agentd-tenant-b" },
		func(r *Ref) { r.AttemptID = "attempt-2" },
		func(r *Ref) { r.ProcessStartTicks++ },
		func(r *Ref) { r.PermitEpoch++ },
	} {
		bad := original
		mutate(&bad)
		_, err := InspectCommand(context.Background(), pool, bad, trusted)
		if !errors.Is(err, ErrMismatch) && !errors.Is(err, ErrNotFound) {
			t.Fatalf("wrong Run/Attempt/process/Permit identity accepted: %v", err)
		}
	}
}

func TestActualWaitCommitSurvivesLostAckAndFreshInspector(t *testing.T) {
	pool := testDatabase(t)
	cmd, original := startOwnedTestProcess(t, "0.2")
	seedAlreadyAuthorizedAttempt(t, pool, original)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	if waitErr == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 7 {
		t.Fatalf("expected actual nonzero child exit: %v / %+v", waitErr, cmd.ProcessState)
	}
	record, err := RecordWaitOutcome(context.Background(), pool, original, cmd.ProcessState, priv)
	if err != nil || record.Status != FailedConfirmed || record.ExitCode != 7 {
		t.Fatalf("supervisor did not durably capture actual Wait result: %+v err=%v", record, err)
	}
	// Caller ACK is deliberately dropped; a fresh process/pool must read
	// the original terminal record with no command re-dispatch.
	other, err := pgxpool.New(context.Background(), os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	for i := 0; i < 2; i++ {
		got, err := InspectCommand(context.Background(), other, original, pub)
		if err != nil || got.State != FailedConfirmed || got.NextAction != Hold ||
			got.CanRetry || got.CanDeclareReleased || got.ExitReceiptDigest == "" ||
			!ed25519.Verify(pub, append([]byte(TerminalDomain), got.ReceiptPayload...), got.ReceiptSignature) {
			t.Fatalf("lost ACK inspect #%d did not read valid terminal: %+v err=%v", i, got, err)
		}
	}
	var n int
	if err := other.QueryRow(context.Background(),
		"SELECT count(*) FROM public.sandbox_agentd_terminal_receipts").Scan(&n); err != nil || n != 1 {
		t.Fatalf("inspection replay duplicated immutable terminal: %d %v", n, err)
	}
}

func TestRealSIGKILLWithoutSourceCommitDoesNotInventExit(t *testing.T) {
	pool := testDatabase(t)
	cmd, original := startOwnedTestProcess(t, "10")
	seedAlreadyAuthorizedAttempt(t, pool, original)
	trusted, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	// Even though the process was definitely SIGKILLed in this TEST, an
	// independent inspecting service never observed its trusted Wait receipt.
	got, err := InspectCommand(context.Background(), pool, original, trusted)
	if err != nil || got.State != Unknown || got.ExitReceiptDigest != "" || got.CanRetry {
		t.Fatalf("worker SIGKILL without source receipt was interpreted as a confirmed result: %+v %v", got, err)
	}
}

func TestForgedWaitPIDOrAttemptCannotCommitTerminal(t *testing.T) {
	pool := testDatabase(t)
	cmd, original := startOwnedTestProcess(t, "0.2")
	seedAlreadyAuthorizedAttempt(t, pool, original)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	bad := original
	bad.ProcessPID += 100
	if _, err := RecordWaitOutcome(context.Background(), pool, bad, cmd.ProcessState, priv); err == nil {
		t.Fatal("forged PID committed authoritative exit")
	}
	bad = original
	bad.AttemptID = "other-attempt"
	if _, err := RecordWaitOutcome(context.Background(), pool, bad, cmd.ProcessState, priv); err == nil {
		t.Fatal("foreign AttemptID committed authoritative exit")
	}
}
