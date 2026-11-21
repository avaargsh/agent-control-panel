package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const validManifest = `{"schema_version":"acp.issue-goal/v1","target":{"tenant_id":"tenant-a","project_id":"project-a","agent_id":"coding-agent","release_id":"release-v1","session_id":"session-123"},"idempotency_key":"issue-123","issue_url":"https://github.com/example/repository/issues/123","target_branch":"main","experiment_baseline_sha":"1111111111111111111111111111111111111111","integration_baseline_sha":"2222222222222222222222222222222222222222","acceptance_rules_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","budget":{"max_tokens":2048,"max_runtime_seconds":3600,"max_sandbox_seconds":1800}}`

func TestPrepareCLIReadsStdinAndReturnsDigestProposal(t *testing.T) {
	var out, diagnostics bytes.Buffer
	err := run([]string{"prepare", "--file", "-"}, strings.NewReader(validManifest), &out, &diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["schema"] != "acp.issue-goal-submission/v1" || result["request_digest"] == "" || result["execution_input_base64"] == "" {
		t.Fatalf("incomplete proposal: %s", out.String())
	}
	if _, exists := result["run_id"]; exists {
		t.Fatal("offline prepare cannot claim a Runtime Run")
	}
}

func TestPrepareCLIRejectsInvalidInputWithoutWritingProposal(t *testing.T) {
	cases := []struct {
		args  []string
		input string
	}{
		{[]string{"prepare", "--file", "-"}, `{"schema_version":"acp.issue-goal/v1"}`},
		{[]string{"prepare", "--file", "-"}, strings.Repeat("a", 32*1024+1)},
		{[]string{"prepare"}, validManifest},
		{[]string{"submit", "--file", "-"}, validManifest},
	}
	for _, tc := range cases {
		var out, diagnostics bytes.Buffer
		if err := run(tc.args, strings.NewReader(tc.input), &out, &diagnostics); err == nil {
			t.Fatal("unsafe invocation accepted")
		}
		if out.Len() != 0 {
			t.Fatalf("failed invocation produced proposal: %s", out.String())
		}
	}
}

func TestPrepareCLIHelpIsSuccessful(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if err := run([]string{"prepare", "--help"}, strings.NewReader(""), &out, &diagnostics); err != nil {
		t.Fatalf("help must not be a command failure: %v", err)
	}
	if !strings.Contains(diagnostics.String(), "Issue Goal manifest path") || out.Len() != 0 {
		t.Fatalf("missing help output: %s", diagnostics.String())
	}
}
