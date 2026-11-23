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

// Parsing must reject duplicate JSON keys *before* any trust-key lookup.
// Otherwise the normal CLI would report missing keys, masking a bundle or
// independent Expected binding interpreted differently by other parsers.
func TestPostfaultCLIRejectsDuplicateBundleAndExpectedKeys(t *testing.T) {
	root := t.TempDir()
	const bundleOK = `{"schema":"acp.postfault-bundle/v1","subject":{},"fault":{"id":"worker-fault-1","kind":"worker_sigkill","at":"2026-11-22T04:00:00Z"},"receipts":[]}`
	const expectedOK = `{"schema":"acp.postfault-expected/v1","subject":{},"fault_id":"worker-fault-1","fault_at":"2026-11-22T04:00:00Z"}`
	cases := []struct {
		name, bundleJSON, expectedJSON, wantError string
	}{
		{
			name:         "duplicate_bundle_schema",
			bundleJSON:   `{"schema":"untrusted","schema":"acp.postfault-bundle/v1","subject":{},"fault":{"id":"worker-fault-1","kind":"worker_sigkill","at":"2026-11-22T04:00:00Z"},"receipts":[]}`,
			expectedJSON: expectedOK, wantError: "postfault bundle is invalid",
		},
		{
			name:         "escaped_duplicate_expected_schema",
			bundleJSON:   bundleOK,
			expectedJSON: `{"\u0073chema":"untrusted","schema":"acp.postfault-expected/v1","subject":{},"fault_id":"worker-fault-1","fault_at":"2026-11-22T04:00:00Z"}`,
			wantError:    "independent authoritative Run/fault/AgentD source binding is invalid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle := filepath.Join(root, tc.name+"-bundle.json")
			expected := filepath.Join(root, tc.name+"-expected.json")
			if err := os.WriteFile(bundle, []byte(tc.bundleJSON), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(expected, []byte(tc.expectedJSON), 0600); err != nil {
				t.Fatal(err)
			}
			// Supply all required mTLS flag names so duplicate JSON validation
			// is reached before trust-key or client-certificate lookup.
			err := run([]string{
				"--bundle", bundle, "--expected", expected, "--trust-dir", root,
				"--agentd-evidence-endpoint", "https://127.0.0.1:9443",
				"--agentd-client-cert", filepath.Join(root, "not-used-client.pem"),
				"--agentd-client-key", filepath.Join(root, "not-used-client.key"),
				"--agentd-server-ca", filepath.Join(root, "not-used-ca.pem"),
				"--agentd-server-name", "agentd.test",
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("duplicate input was not rejected at the parsing boundary: %v", err)
			}
		})
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
