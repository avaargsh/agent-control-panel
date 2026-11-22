//go:build linux

package agentd

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Test-only process owner. It is not a production AgentD server, Guard PEP,
// remote execution API or authority to start unapproved commands. This child
// actually starts a disposable OS process, persists its exact original
// identity, and may be SIGKILLed to exercise crash/ACK uncertainty.
func TestOriginalAgentDWorkerChild(t *testing.T) {
	mode := os.Getenv("AGENTD_INSPECT_CHILD_MODE")
	if mode == "" {
		return
	}
	if mode != "committed" && mode != "uncommitted" {
		t.Fatal("unexpected child fixture mode")
	}
	dsn := os.Getenv("SANDBOX_JOURNAL_TEST_DSN")
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	duration := "2"
	if mode == "committed" {
		duration = "0.2"
	}
	cmd, ref := startOwnedTestProcess(t, duration)
	seedAlreadyAuthorizedAttempt(t, pool, ref)
	if mode == "committed" {
		if err := cmd.Wait(); err == nil {
			t.Fatal("expected actual nonzero Wait")
		}
		key, err := base64.StdEncoding.Strict().DecodeString(os.Getenv("AGENTD_INSPECT_TEST_SIGNER"))
		if err != nil || len(key) != ed25519.PrivateKeySize {
			t.Fatal("test child has no valid ephemeral signing key")
		}
		if _, err := RecordWaitOutcome(context.Background(), pool, ref, cmd.ProcessState,
			ed25519.PrivateKey(key)); err != nil {
			t.Fatal("source terminal commit:", err)
		}
		fmt.Println("SOURCE_TERMINAL_COMMITTED")
	} else {
		fmt.Println("SOURCE_ATTEMPT_UNKNOWN")
	}
	// The parent SIGKILLs this worker after the journal transaction commits.
	// It never receives an application ACK, and no retry is allowed.
	time.Sleep(time.Minute)
	t.Fatal("test worker was not killed")
}

func TestRealAgentDWorkerSIGKILLBeforeAndAfterTerminalCommit(t *testing.T) {
	for _, mode := range []string{"committed", "uncommitted"} {
		t.Run(mode, func(t *testing.T) {
			pool := testDatabase(t)
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			worker := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOriginalAgentDWorkerChild$", "-test.timeout=15s")
			worker.Env = append(os.Environ(), "AGENTD_INSPECT_CHILD_MODE="+mode,
				"AGENTD_INSPECT_TEST_SIGNER="+base64.StdEncoding.EncodeToString(priv))
			stdout, err := worker.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if worker.ProcessState == nil {
					_ = worker.Process.Kill()
					_ = worker.Wait()
				}
			})
			line, err := bufio.NewReader(stdout).ReadString('\n')
			expectedLine := "SOURCE_ATTEMPT_UNKNOWN\n"
			if mode == "committed" {
				expectedLine = "SOURCE_TERMINAL_COMMITTED\n"
			}
			if err != nil || line != expectedLine {
				t.Fatalf("real worker did not persist source state before SIGKILL: line=%q err=%v", line, err)
			}
			if err := worker.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			exitErr := worker.Wait()
			var killed *exec.ExitError
			if !errors.As(exitErr, &killed) {
				t.Fatalf("expected actual worker SIGKILL: %v", exitErr)
			}
			if ws, ok := killed.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("worker did not die from SIGKILL: %v", killed.Sys())
			}
			// The inspection is in a fresh DB pool, not the killed worker.
			other, err := pgxpool.New(context.Background(), os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			var pid int
			var start int64
			var boot string
			err = other.QueryRow(ctx, `SELECT process_pid,process_start_ticks,host_boot_id
				FROM public.sandbox_agentd_attempts
				WHERE tenant_id='agentd-tenant-a' AND sandbox_uid='sandbox-uid-1'
				  AND command_id='command-1' AND attempt_id='executor-attempt-1'`).Scan(&pid, &start, &boot)
			if err != nil {
				t.Fatal(err)
			}
			original := Ref{
				TenantID:           "agentd-tenant-a",
				RunID:              "11111111-1111-4111-8111-111111111111",
				RuntimeAttemptID:   "runtime-attempt-1",
				SandboxUID:         "sandbox-uid-1",
				CommandID:          "command-1",
				AttemptID:          "executor-attempt-1",
				ProviderCommandUID: "provider-command-uid-1",
				RequestDigest:      "sha256:" + strings.Repeat("a", 64),
				GuardPermitID:      "guard-permit-1",
				PermitEpoch:        7,
				ProcessPID:         pid,
				ProcessStartTicks:  uint64(start),
				HostBootID:         boot,
			}
			got, err := InspectCommand(ctx, other, original, pub)
			if err != nil || got.CanRetry || got.CanDeclareReleased || got.NextAction != Hold {
				t.Fatalf("source inspection authorized blind effect after worker SIGKILL: %+v %v", got, err)
			}
			if mode == "committed" && (got.State != FailedConfirmed || got.ExitReceiptDigest == "") {
				t.Fatalf("worker SIGKILL erased original committed terminal: %+v", got)
			}
			if mode == "uncommitted" && (got.State != Unknown || got.ExitReceiptDigest != "") {
				t.Fatalf("worker SIGKILL before Wait commit fabricated terminal: %+v", got)
			}
			t.Logf("AGENTD_ORIGINAL_INSPECT_SIGKILL_%s: state=%s next=HOLD dispatch_count=1", mode, got.State)
		})
	}
}
