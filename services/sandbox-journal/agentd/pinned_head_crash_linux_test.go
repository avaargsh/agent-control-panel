//go:build linux

package agentd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func crashHeadFixture(t *testing.T) (Ref, []JournaledInspection, ed25519.PublicKey, ed25519.PrivateKey, ed25519.PublicKey, time.Time) {
	t.Helper()
	authority := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	source := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	ref := Ref{TenantID: "tenant-1", RunID: "run-1", RuntimeAttemptID: "runtime-1", SandboxUID: "sandbox-1", CommandID: "command-1", AttemptID: "attempt-1", ProviderCommandUID: "provider-1", RequestDigest: "sha256:" + strings.Repeat("a", 64), GuardPermitID: "permit-1", PermitEpoch: 1, ProcessPID: 123, ProcessStartTicks: 456, HostBootID: "11111111-1111-4111-8111-111111111111"}
	var events []JournaledInspection
	previous := ""
	for i := uint64(1); i <= 2; i++ {
		event := InspectEvent{Schema: InspectSchema, Source: "agentd.inspect", Ref: ref, ObservedAt: now.Add(-time.Minute + time.Duration(i)*time.Second).Format(time.RFC3339Nano), InspectCount: i, JournalVersion: i, PreviousDigest: previous, State: Unknown, NextAction: Hold, DispatchCount: 1}
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		previous = digest(raw)
		events = append(events, JournaledInspection{Event: event, Payload: raw, Signature: ed25519.Sign(source, append([]byte(InspectDomain), raw...)), Digest: previous})
	}
	return ref, events, authority.Public().(ed25519.PublicKey), authority, source.Public().(ed25519.PublicKey), now
}

func crashHead(row JournaledInspection) InspectHead {
	return InspectHead{InspectCount: row.Event.InspectCount, JournalVersion: row.Event.JournalVersion, Digest: row.Digest}
}

func crashAdvance(t *testing.T, store *PinnedHeadStore) error {
	t.Helper()
	ref, events, authorityKey, signer, sourceKey, now := crashHeadFixture(t)
	raw, err := json.Marshal(headGrantWireFixture{Schema: "acp.agentd-pinned-head-grant/v1", Ref: ref, Head: crashHead(events[1]), IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(signer, append([]byte("acp.agentd-pinned-head-grant/v1\x00"), raw...))
	_, err = store.Advance(ref, crashHead(events[0]), raw, sig, events, authorityKey, sourceKey, now)
	return err
}

// The child reports an out-of-band fault-injection checkpoint, not an
// application ACK. The parent kills it before any normal process completion.
func TestPinnedHeadCrashChild(t *testing.T) {
	mode := os.Getenv("ACP_HEAD_CRASH_MODE")
	if mode == "" {
		return
	}
	store, err := OpenPinnedHeadStore(os.Getenv("ACP_HEAD_CRASH_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	switch mode {
	case "committed":
		if err := crashAdvance(t, store); err != nil {
			t.Fatal(err)
		}
		fmt.Println("CHECKPOINT")
		for {
			time.Sleep(time.Hour)
		}
	case "staged":
		// Exercise real lock ownership and an orphaned uncommitted file.
		// This is not instrumentation of Advance's internal write path.
		err := store.locked(func(fd int) error {
			f, err := syscall.Openat(fd, ".head-interrupted", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC, 0600)
			if err != nil {
				return err
			}
			file := os.NewFile(uintptr(f), "staged")
			if _, err := file.Write([]byte("partial staging data")); err != nil {
				file.Close()
				return err
			}
			if err := file.Sync(); err != nil {
				file.Close()
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
			fmt.Println("CHECKPOINT")
			for {
				time.Sleep(time.Hour)
			}
		})
		t.Fatal(err)
	case "read":
		ref, _, _, _, _, _ := crashHeadFixture(t)
		got, err := store.Read(ref)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("HEAD=%d:%s\n", got.InspectCount, got.Digest)
	default:
		t.Fatal("unknown crash test mode")
	}
}

func crashCommand(ctx context.Context, dir, mode string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPinnedHeadCrashChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "ACP_HEAD_CRASH_DIR="+dir, "ACP_HEAD_CRASH_MODE="+mode)
	return cmd
}

func killHeadChild(t *testing.T, dir, mode string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := crashCommand(ctx, dir, mode)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "CHECKPOINT" {
		t.Fatalf("child failed before checkpoint: %q %v", line, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	if err == nil || !cmd.ProcessState.Sys().(syscall.WaitStatus).Signaled() || cmd.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("expected real SIGKILL: %v", err)
	}
}

func TestPinnedHeadStoreSIGKILLRecovery(t *testing.T) {
	ref, events, _, _, _, _ := crashHeadFixture(t)
	for _, mode := range []string{"staged", "committed"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			store, err := OpenPinnedHeadStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Enroll(ref, crashHead(events[0])); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			killHeadChild(t, dir, mode)
			want := crashHead(events[0])
			if mode == "committed" {
				want = crashHead(events[1])
			} else if _, err := os.Stat(filepath.Join(dir, ".head-interrupted")); err != nil {
				t.Fatalf("expected orphan staging file: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			out, err := crashCommand(ctx, dir, "read").CombinedOutput()
			if err != nil || !strings.Contains(string(out), fmt.Sprintf("HEAD=%d:%s\n", want.InspectCount, want.Digest)) {
				t.Fatalf("fresh process did not recover accepted head: %s %v", out, err)
			}
			store, err = OpenPinnedHeadStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			err = crashAdvance(t, store)
			if (mode == "committed" && err == nil) || (mode == "staged" && err != nil) {
				t.Fatalf("unexpected stale CAS or fresh continuation outcome: %v", err)
			}
			if got, err := store.Read(ref); err != nil || got != crashHead(events[1]) {
				t.Fatalf("final floor not preserved: %+v %v", got, err)
			}
		})
	}
}
