//go:build linux

package postfault

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// This exercises an ACTUAL disposable OS-command side effect with a lost
// acknowledgement and a real worker-process SIGKILL. It is not AgentD,
// a Guard Permit, an authenticated Sandbox journal or a terminal receipt.
func TestLocalUnknownCommandAfterSIGKILLRemainsBlocked(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	before := killLocalUnknownCommandProcess(t, root)
	effectBefore, err := os.ReadFile(filepath.Join(root, localUnknownEffectFile))
	if err != nil {
		t.Fatal(err)
	}
	after, err := inspectLocalUnknownCommandProcess(t, root, before)
	if err != nil || after != before {
		t.Fatalf("independent process failed to inspect durable UNKNOWN: before=%+v after=%+v err=%v", before, after, err)
	}
	if after.Status != "UNKNOWN" || after.DispatchCount != 1 ||
		after.TerminalReceipt != "" || after.CanRetry || after.CanDeclareSuccess {
		t.Fatalf("unknown command was promoted to terminal success or re-dispatch: %+v", after)
	}
	effectAfter, err := os.ReadFile(filepath.Join(root, localUnknownEffectFile))
	if err != nil || !bytes.Equal(effectBefore, effectAfter) {
		t.Fatalf("post-fault inspection changed the actual external effect: %v", err)
	}
	t.Log("LOCAL_UNKNOWN_COMMAND_SIGKILL_HOLD_CONFIRMED: one OS effect, dispatch=1, no terminal ACK, no retry")
}

func TestLocalUnknownCommandRejectsForgedReconciliation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string, *localUnknownReceipt)
	}{
		{"wrong_run", func(_ *testing.T, _ string, r *localUnknownReceipt) { r.RunID = "other-run" }},
		{"wrong_attempt", func(_ *testing.T, _ string, r *localUnknownReceipt) { r.AttemptID = "other-attempt" }},
		{"wrong_command", func(_ *testing.T, _ string, r *localUnknownReceipt) { r.CommandID = "other-command" }},
		{"missing_effect", func(t *testing.T, root string, _ *localUnknownReceipt) {
			if err := os.Remove(filepath.Join(root, localUnknownEffectFile)); err != nil {
				t.Fatal(err)
			}
		}},
		{"duplicated_effect", func(t *testing.T, root string, _ *localUnknownReceipt) {
			f, err := os.OpenFile(filepath.Join(root, localUnknownEffectFile), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write([]byte("duplicate-external-effect")); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{"fabricated_terminal", func(t *testing.T, root string, r *localUnknownReceipt) {
			stored := *r
			stored.Status = "EXITED"
			stored.TerminalReceipt = "forged-local-exit"
			rewriteLocalUnknownJournal(t, root, stored)
		}},
		{"double_dispatch", func(t *testing.T, root string, r *localUnknownReceipt) {
			stored := *r
			stored.DispatchCount = 2
			rewriteLocalUnknownJournal(t, root, stored)
		}},
		{"replaced_workspace_identical_files", func(t *testing.T, root string, _ *localUnknownReceipt) {
			old := root + "-replaced"
			if err := os.Rename(root, old); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{localUnknownEffectFile, localUnknownJournalFile} {
				raw, err := os.ReadFile(filepath.Join(old, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"symlink_effect", func(t *testing.T, root string, _ *localUnknownReceipt) {
			effect := filepath.Join(root, localUnknownEffectFile)
			if err := os.Remove(effect); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(filepath.Dir(root), "outside-effect")
			if err := os.WriteFile(outside, []byte("foreign"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, effect); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "workspace")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			expected := killLocalUnknownCommandProcess(t, root)
			tc.mutate(t, root, &expected)
			if _, err := inspectLocalUnknownCommandProcess(t, root, expected); err == nil {
				t.Fatal("forged or unsafe UNKNOWN command evidence was accepted")
			}
		})
	}
}

func rewriteLocalUnknownJournal(t *testing.T, root string, receipt localUnknownReceipt) {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, localUnknownJournalFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
