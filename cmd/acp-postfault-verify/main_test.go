package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/postfault"
)

func TestPostfaultCLIFailsClosedWhenAuthoritativeInputsMissing(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "partial.json")
	if err := os.WriteFile(existing, []byte(`{"schema":"acp.postfault-bundle/v1","receipts":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		nil,
		{"--bundle", filepath.Join(root, "missing.json"), "--trust-dir", root},
		{"--bundle", existing, "--trust-dir", root},
		{"--bundle", existing, "--trust-dir", filepath.Join(root, "missing")},
	} {
		if err := run(args); err == nil {
			t.Fatalf("missing or self-asserted Golden Path recovery evidence accepted: %v", args)
		}
	}
}

func TestPostfaultCLIDoesNotFollowSymlinkToInjectedBundle(t *testing.T) {
	root := t.TempDir()
	realPath := filepath.Join(root, "recovery.json")
	if err := os.WriteFile(realPath, []byte(`{"schema":"acp.postfault-bundle/v1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "latest")
	if err := os.Symlink(realPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := privateBoundedInput(link); err == nil {
		t.Fatal("untrusted evidence symlink accepted")
	}
}

func TestPostfaultCLIRefusesMalformedPayloadWithoutLeakingBytes(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "sensitive.json")
	if err := os.WriteFile(p, []byte(`{"schema":"SECRET-NOT-FOR-LOGGING","extra":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"--bundle", p, "--trust-dir", root})
	if err == nil || strings.Contains(err.Error(), "SECRET-NOT-FOR-LOGGING") {
		t.Fatalf("unsafe malformed bundle error: %v", err)
	}
}

func TestExpectedBindingRejectsUnrelatedHistoricalRunAndFault(t *testing.T) {
	subject := postfault.Subject{
		TenantID: "tenant-1", RunID: "runtime-run-1",
		SessionID: "session-1", WorkflowID: "agent-run/v1/runtime-run-1",
		GuardOperationID: "operation-1",
	}
	at := time.Date(2026, 11, 21, 7, 0, 0, 0, time.UTC)
	bundle := postfault.Bundle{
		Schema:  postfault.BundleVersion,
		Subject: subject,
		Fault:   postfault.Fault{ID: "worker-fault-1", Kind: "worker_sigkill", At: at},
	}
	expected := expectedBinding{Subject: subject, FaultID: "worker-fault-1", FaultAt: at}
	if err := matchesExpected(bundle, expected); err != nil {
		t.Fatalf("authoritatively bound same Run was rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*expectedBinding)
	}{
		{"different_tenant", func(e *expectedBinding) { e.Subject.TenantID = "tenant-2" }},
		{"different_run", func(e *expectedBinding) { e.Subject.RunID = "runtime-run-2" }},
		{"different_workflow", func(e *expectedBinding) { e.Subject.WorkflowID = "agent-run/v1/other" }},
		{"different_guard_operation", func(e *expectedBinding) { e.Subject.GuardOperationID = "operation-2" }},
		{"different_fault", func(e *expectedBinding) { e.FaultID = "other-fault" }},
		{"different_injection_time", func(e *expectedBinding) { e.FaultAt = e.FaultAt.Add(time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyExpected := expected
			tc.edit(&copyExpected)
			if err := matchesExpected(bundle, copyExpected); err == nil {
				t.Fatal("signed evidence for another Run, operation or fault was accepted")
			}
		})
	}
}
