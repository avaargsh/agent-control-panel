//go:build linux

package postfault

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	localUnknownJournalFile = ".acp-local-unknown-journal"
	localUnknownEffectFile  = ".acp-local-command-effect"
	localUnknownEffectBytes = "acp-local-external-command-once"
)

// This is deliberately a *test-only, untrusted local fixture*. A filesystem
// record is not the authoritative Sandbox/AgentD Command Journal and cannot
// certify terminal exit, Guard authorization or permission to re-dispatch.
type localUnknownReceipt struct {
	Source            string
	TenantID          string
	RunID             string
	SandboxUID        string
	CommandID         string
	AttemptID         string
	RootDevice        uint64
	RootInode         uint64
	EffectDigest      string
	Status            string
	DispatchCount     uint64
	TerminalReceipt   string
	CanRetry          bool
	CanDeclareSuccess bool
}

// A separate OS subprocess executes /bin/sh, which writes to a disposable
// owner-private workspace file. The local journal's UNKNOWN fact is synced
// before invoking the process, so a lost ACK is never permission to retry.
func prepareLocalUnknownCommand(root string) (localUnknownReceipt, error) {
	dirfd, stat, err := openLocalWorkspaceRoot(root)
	if err != nil {
		return localUnknownReceipt{}, err
	}
	defer syscall.Close(dirfd)
	sum := sha256.Sum256([]byte(localUnknownEffectBytes))
	record := localUnknownReceipt{
		Source:   "LOCAL_UNTRUSTED_PROCESS_FIXTURE",
		TenantID: "tenant-local", RunID: "run-local-1",
		SandboxUID: "sandbox-local-1", CommandID: "command-local-1",
		AttemptID: "attempt-local-1", RootDevice: uint64(stat.Dev),
		RootInode: stat.Ino, EffectDigest: "sha256:" + hex.EncodeToString(sum[:]),
		Status: "UNKNOWN", DispatchCount: 1,
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return localUnknownReceipt{}, err
	}
	journalFD, err := syscall.Openat(dirfd, localUnknownJournalFile,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return localUnknownReceipt{}, errors.New("local unknown journal unavailable")
	}
	if err := writeAndSyncLocalFD(journalFD, raw); err != nil {
		return localUnknownReceipt{}, err
	}
	// The caller cannot infer success from a command-launch attempt.
	effectFD, err := syscall.Openat(dirfd, localUnknownEffectFile,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return localUnknownReceipt{}, errors.New("local external effect already exists")
	}
	effect := os.NewFile(uintptr(effectFD), "disposable-os-command-output")
	// No untrusted input is interpolated into this constant local command.
	command := exec.Command("/bin/sh", "-c", "printf acp-local-external-command-once")
	command.Stdout = effect
	runErr := command.Run()
	syncErr := effect.Sync()
	closeErr := effect.Close()
	if runErr != nil || syncErr != nil || closeErr != nil {
		return localUnknownReceipt{}, fmt.Errorf("disposable external command/write failed: cmd=%v sync=%v close=%v", runErr, syncErr, closeErr)
	}
	if err := syscall.Fsync(dirfd); err != nil {
		return localUnknownReceipt{}, errors.New("disposable external effect directory sync failed")
	}
	actual, err := readLocalWorkspaceFile(dirfd, localUnknownEffectFile, 4096)
	if err != nil || !bytes.Equal(actual, []byte(localUnknownEffectBytes)) {
		return localUnknownReceipt{}, errors.New("external OS command did not persist expected bytes")
	}
	return record, nil
}

// The inspector does not start a command. It returns UNKNOWN/HOLD even when
// it can see the external side effect: bytes on disk are not an exit receipt.
func inspectLocalUnknownCommand(root string, expected localUnknownReceipt) (localUnknownReceipt, error) {
	dirfd, stat, err := openLocalWorkspaceRoot(root)
	if err != nil {
		return localUnknownReceipt{}, err
	}
	defer syscall.Close(dirfd)
	if expected.RootDevice != uint64(stat.Dev) || expected.RootInode != stat.Ino {
		return localUnknownReceipt{}, errors.New("local workspace identity changed")
	}
	raw, err := readLocalWorkspaceFile(dirfd, localUnknownJournalFile, 4096)
	if err != nil {
		return localUnknownReceipt{}, err
	}
	var journal localUnknownReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&journal) != nil || decoder.Decode(new(any)) != io.EOF {
		return localUnknownReceipt{}, errors.New("invalid local journal")
	}
	canonical, err := json.Marshal(journal)
	if err != nil || !bytes.Equal(raw, canonical) {
		return localUnknownReceipt{}, errors.New("local journal duplicate or noncanonical fields")
	}
	if journal != expected || journal.Source != "LOCAL_UNTRUSTED_PROCESS_FIXTURE" ||
		journal.TenantID == "" || journal.RunID == "" || journal.SandboxUID == "" ||
		journal.CommandID == "" || journal.AttemptID == "" ||
		journal.Status != "UNKNOWN" || journal.DispatchCount != 1 ||
		journal.TerminalReceipt != "" || journal.CanRetry || journal.CanDeclareSuccess {
		return localUnknownReceipt{}, errors.New("unknown command identity/dispatch/receipt fence violated")
	}
	effect, err := readLocalWorkspaceFile(dirfd, localUnknownEffectFile, 4096)
	if err != nil {
		return localUnknownReceipt{}, err
	}
	digest := sha256.Sum256(effect)
	if journal.EffectDigest != "sha256:"+hex.EncodeToString(digest[:]) ||
		!bytes.Equal(effect, []byte(localUnknownEffectBytes)) {
		return localUnknownReceipt{}, errors.New("external side-effect bytes changed")
	}
	return journal, nil
}

func TestLocalUnknownCommandChild(t *testing.T) {
	if os.Getenv("ACP_LOCAL_UNKNOWN_CHILD") != "1" {
		return
	}
	root := os.Getenv("ACP_LOCAL_UNKNOWN_ROOT")
	mode := os.Getenv("ACP_LOCAL_UNKNOWN_MODE")
	var record localUnknownReceipt
	var err error
	switch mode {
	case "dispatch":
		record, err = prepareLocalUnknownCommand(root)
	case "inspect":
		var raw []byte
		raw, err = base64.StdEncoding.DecodeString(os.Getenv("ACP_LOCAL_UNKNOWN_EXPECTED"))
		if err == nil {
			err = json.Unmarshal(raw, &record)
		}
		if err == nil {
			record, err = inspectLocalUnknownCommand(root, record)
		}
	default:
		t.Fatal("unsupported local unknown process mode")
	}
	if err != nil {
		t.Fatal("disposable command inspection rejected:", err)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("LOCAL_UNKNOWN_COMMAND %s\n", raw)
	if mode == "dispatch" {
		// The harness receives a readiness marker, NOT a trusted terminal
		// ACK. The child stays alive until the parent delivers real SIGKILL.
		_, _ = os.Stdin.Read(make([]byte, 1))
	}
}

func localUnknownChild(t *testing.T, mode, root, expected string) (*exec.Cmd, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalUnknownCommandChild$", "-test.v")
	cmd.Env = []string{
		"ACP_LOCAL_UNKNOWN_CHILD=1",
		"ACP_LOCAL_UNKNOWN_MODE=" + mode,
		"ACP_LOCAL_UNKNOWN_ROOT=" + root,
		"ACP_LOCAL_UNKNOWN_EXPECTED=" + expected,
	}
	return cmd, cancel
}

func killLocalUnknownCommandProcess(t *testing.T, root string) localUnknownReceipt {
	t.Helper()
	cmd, cancel := localUnknownChild(t, "dispatch", root, "")
	defer cancel()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var before localUnknownReceipt
	found := false
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "LOCAL_UNKNOWN_COMMAND ") {
			found = json.Unmarshal([]byte(strings.TrimPrefix(scanner.Text(), "LOCAL_UNKNOWN_COMMAND ")), &before) == nil
			break
		}
	}
	if !found {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("no persisted local command readiness marker: %v", scanner.Err())
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	err = cmd.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("local worker was not killed: %v", err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("fault injection was not SIGKILL: %v", err)
	}
	return before
}

func inspectLocalUnknownCommandProcess(t *testing.T, root string, expected localUnknownReceipt) (localUnknownReceipt, error) {
	t.Helper()
	raw, err := json.Marshal(expected)
	if err != nil {
		return localUnknownReceipt{}, err
	}
	cmd, cancel := localUnknownChild(t, "inspect", root, base64.StdEncoding.EncodeToString(raw))
	defer cancel()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return localUnknownReceipt{}, fmt.Errorf("new process refused UNKNOWN inspection: %w: %s", err, string(out))
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "LOCAL_UNKNOWN_COMMAND ") {
			var actual localUnknownReceipt
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "LOCAL_UNKNOWN_COMMAND ")), &actual); err != nil {
				return localUnknownReceipt{}, err
			}
			return actual, nil
		}
	}
	return localUnknownReceipt{}, errors.New("no independently reread local UNKNOWN command record")
}
