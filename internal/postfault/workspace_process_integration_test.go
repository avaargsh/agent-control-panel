//go:build linux

package postfault

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// All processes and signing/provisioning in this test are local disposable
// fixtures. This is NOT a SandboxService, AgentD, Permit, or production proof.
type localWorkspaceSnapshot struct {
	TenantID       string
	RunID          string
	LeaseID        string
	SandboxUID     string
	WorkspaceID    string
	Generation     uint64
	RootDevice     uint64
	RootInode      uint64
	SentinelDigest string
}

func TestPhysicalWorkspaceSurvivesWorkerSIGKILL(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux openat and SIGKILL probe")
	}
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	before := killLocalWorkspaceProcess(t, root)
	after, err := inspectLocalWorkspaceProcess(t, root, before)
	if err != nil || before != after {
		t.Fatalf("fresh process failed to re-read identical physical workspace: before=%+v after=%+v err=%v", before, after, err)
	}
	if before.RootDevice == 0 || before.RootInode == 0 || before.SentinelDigest == "" {
		t.Fatal("local workspace has no physical directory/byte evidence")
	}
	t.Logf("LOCAL_WORKSPACE_SIGKILL_CONFIRMED run=%s lease=%s sandbox_uid=%s workspace=%s device=%d inode=%d digest=%s",
		before.RunID, before.LeaseID, before.SandboxUID, before.WorkspaceID,
		before.RootDevice, before.RootInode, before.SentinelDigest)
}

func TestPhysicalWorkspaceRecoveryRejectsCorruptionAndStaleBinding(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux openat and SIGKILL probe")
	}
	for _, scenario := range []struct {
		name   string
		change func(*testing.T, string, *localWorkspaceSnapshot)
	}{
		{"changed_bytes", func(t *testing.T, root string, _ *localWorkspaceSnapshot) {
			if err := os.WriteFile(filepath.Join(root, ".acp-continuity"), []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"same_bytes_new_directory", func(t *testing.T, root string, _ *localWorkspaceSnapshot) {
			backup := root + "-old"
			if err := os.Rename(root, backup); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{".acp-continuity", ".acp-workspace.json"} {
				raw, err := os.ReadFile(filepath.Join(backup, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"symlink_sentinel", func(t *testing.T, root string, _ *localWorkspaceSnapshot) {
			sentinel := filepath.Join(root, ".acp-continuity")
			if err := os.Remove(sentinel); err != nil {
				t.Fatal(err)
			}
			external := filepath.Join(filepath.Dir(root), "external")
			if err := os.WriteFile(external, []byte("other"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(external, sentinel); err != nil {
				t.Fatal(err)
			}
		}},
		{"other_run", func(_ *testing.T, _ string, s *localWorkspaceSnapshot) { s.RunID = "other-run" }},
		{"changed_generation", func(_ *testing.T, _ string, s *localWorkspaceSnapshot) { s.Generation++ }},
		{"changed_sandbox_uid", func(_ *testing.T, _ string, s *localWorkspaceSnapshot) { s.SandboxUID = "other-sandbox" }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "workspace")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			before := killLocalWorkspaceProcess(t, root)
			scenario.change(t, root, &before)
			if _, err := inspectLocalWorkspaceProcess(t, root, before); err == nil {
				t.Fatal("corrupt or unrelated physical workspace accepted")
			}
		})
	}
}

func TestLocalWorkspaceProcessChild(t *testing.T) {
	if os.Getenv("ACP_POSTFAULT_LOCAL_CHILD") != "1" {
		return
	}
	root := os.Getenv("ACP_POSTFAULT_LOCAL_ROOT")
	var result localWorkspaceSnapshot
	var err error
	switch os.Getenv("ACP_POSTFAULT_LOCAL_MODE") {
	case "prepare":
		result, err = prepareLocalWorkspace(root, []byte("disposable physically persisted workspace bytes"))
	case "inspect":
		var raw []byte
		raw, err = base64.StdEncoding.DecodeString(os.Getenv("ACP_POSTFAULT_LOCAL_EXPECTED"))
		if err == nil {
			err = json.Unmarshal(raw, &result)
		}
		if err == nil {
			result, err = inspectLocalWorkspace(root, result)
		}
	default:
		t.Fatal("unknown local-only process mode")
	}
	if err != nil {
		t.Fatal("physical workspace observation denied:", err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("LOCAL_WORKSPACE %s\n", payload)
	if os.Getenv("ACP_POSTFAULT_LOCAL_MODE") == "prepare" {
		// Keep the real process alive until the parent delivers SIGKILL.
		_, _ = os.Stdin.Read(make([]byte, 1))
	}
}

func localWorkspaceChild(t *testing.T, mode, root, expected string) (*exec.Cmd, *bufio.Scanner, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalWorkspaceProcessChild$", "-test.v")
	cmd.Env = []string{
		"ACP_POSTFAULT_LOCAL_CHILD=1", "ACP_POSTFAULT_LOCAL_MODE=" + mode,
		"ACP_POSTFAULT_LOCAL_ROOT=" + root, "ACP_POSTFAULT_LOCAL_EXPECTED=" + expected,
	}
	return cmd, nil, cancel
}

func killLocalWorkspaceProcess(t *testing.T, root string) localWorkspaceSnapshot {
	t.Helper()
	cmd, _, cancel := localWorkspaceChild(t, "prepare", root, "")
	defer cancel()
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(out)
	var before localWorkspaceSnapshot
	found := false
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "LOCAL_WORKSPACE ") {
			found = json.Unmarshal([]byte(strings.TrimPrefix(scanner.Text(), "LOCAL_WORKSPACE ")), &before) == nil
			break
		}
	}
	if !found {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("no durable pre-fault workspace snapshot")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = in.Close()
	err = cmd.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("fault injection did not kill a process: %v", err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("not SIGKILL: %v", err)
	}
	return before
}

func inspectLocalWorkspaceProcess(t *testing.T, root string, expected localWorkspaceSnapshot) (localWorkspaceSnapshot, error) {
	t.Helper()
	raw, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	cmd, _, cancel := localWorkspaceChild(t, "inspect", root, base64.StdEncoding.EncodeToString(raw))
	defer cancel()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return localWorkspaceSnapshot{}, fmt.Errorf("fresh inspector refused workspace: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "LOCAL_WORKSPACE ") {
			var actual localWorkspaceSnapshot
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "LOCAL_WORKSPACE ")), &actual); err != nil {
				return actual, err
			}
			return actual, nil
		}
	}
	return localWorkspaceSnapshot{}, errors.New("no physical readback from fresh process")
}
