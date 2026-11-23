package issuegoal

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

const validManifest = `{"schema_version":"acp.issue-goal/v1","target":{"tenant_id":"tenant-a","project_id":"project-a","agent_id":"coding-agent","release_id":"release-v1","session_id":"session-123"},"idempotency_key":"issue-123","issue_url":"https://github.com/example/repository/issues/123","issue_snapshot_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","target_branch":"main","experiment_baseline_sha":"1111111111111111111111111111111111111111","integration_baseline_sha":"2222222222222222222222222222222222222222","acceptance_rules_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","budget":{"max_tokens":2048,"max_runtime_seconds":3600,"max_sandbox_seconds":1800}}`

func TestPreparePinsExactInputForRunIntent(t *testing.T) {
	prepared, err := Prepare([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Schema != "acp.issue-goal-submission/v1" || prepared.RequestDigest == "" || prepared.IdempotencyKey != "issue-123" {
		t.Fatalf("unexpected preparation: %+v", prepared)
	}
	raw, err := base64.StdEncoding.DecodeString(prepared.ExecutionInputBase64)
	if err != nil {
		t.Fatal(err)
	}
	var input Input
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	if input.IssueURL != "https://github.com/example/repository/issues/123" || input.Kind != "github.issue.fix.v1" || input.IntegrationBaselineSHA == input.ExperimentBaselineSHA {
		t.Fatalf("missing pinned goal: %+v", input)
	}
	intent := runintent.Intent{
		TenantID: prepared.Target.TenantID, ProjectID: prepared.Target.ProjectID,
		AgentID: prepared.Target.AgentID, ReleaseID: prepared.Target.ReleaseID,
		SessionID: prepared.Target.SessionID, IdempotencyKey: prepared.IdempotencyKey,
		RequestDigest: prepared.RequestDigest,
	}
	if err := runintent.VerifyExecutionInput(intent, raw); err != nil {
		t.Fatalf("does not match ACP execution input: %v", err)
	}
	repeat, err := Prepare([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	if repeat != prepared {
		t.Fatal("same input must produce exactly identical submission")
	}
}

func TestPrepareRejectsUnsafeOrAmbiguousGoal(t *testing.T) {
	cases := map[string]string{
		"casefold duplicate manifest field": strings.Replace(validManifest, `"issue_url":`, `"Issue_URL":"https://github.com/example/repository/issues/99","issue_url":`, 1),
		"unknown manifest field":            strings.Replace(validManifest, `"schema_version":`, `"unexpected":1,"schema_version":`, 1),
		"duplicate manifest field":          strings.Replace(validManifest, `"issue_url":`, `"issue_url":"https://github.com/example/repository/issues/99","issue_url":`, 1),
		"unsupported version":               strings.Replace(validManifest, `acp.issue-goal/v1`, `acp.issue-goal/v2`, 1),
		"fake github domain":                strings.Replace(validManifest, `github.com/example`, `github.com.evil.invalid/example`, 1),
		"issue url credential":              strings.Replace(validManifest, `https://github.com/`, `https://token@github.com/`, 1),
		"issue url query":                   strings.Replace(validManifest, `/issues/123`, `/issues/123?token=secret`, 1),
		"issue url empty query delimiter":   strings.Replace(validManifest, `/issues/123`, `/issues/123?`, 1),
		"issue url not issue":               strings.Replace(validManifest, `/issues/123`, `/pull/123`, 1),
		"issue url encoded path":            strings.Replace(validManifest, `/issues/123`, `/issues/%31%32%33`, 1),
		"unfixed baseline":                  strings.Replace(validManifest, `"integration_baseline_sha":"2222222222222222222222222222222222222222"`, `"integration_baseline_sha":"main"`, 1),
		"bad rules digest":                  strings.Replace(validManifest, `sha256:3333333333333333333333333333333333333333333333333333333333333333`, `sha256:bad`, 1),
		"unsafe branch":                     strings.Replace(validManifest, `"target_branch":"main"`, `"target_branch":"../main"`, 1),
		"zero budget":                       strings.Replace(validManifest, `"max_tokens":2048`, `"max_tokens":0`, 1),
		"over-budget sandbox":               strings.Replace(validManifest, `"max_sandbox_seconds":1800`, `"max_sandbox_seconds":3601`, 1),
		"missing target":                    strings.Replace(validManifest, `"tenant_id":"tenant-a"`, `"tenant_id":""`, 1),
		"empty idempotency":                 strings.Replace(validManifest, `"idempotency_key":"issue-123"`, `"idempotency_key":""`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Prepare([]byte(raw)); err == nil {
				t.Fatal("unsafe goal was accepted")
			}
		})
	}
}

func TestPrepareChangesDigestWhenPinnedInputOrScopeChanges(t *testing.T) {
	first, err := Prepare([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		strings.Replace(validManifest, `"tenant_id":"tenant-a"`, `"tenant_id":"tenant-b"`, 1),
		strings.Replace(validManifest, `"idempotency_key":"issue-123"`, `"idempotency_key":"issue-456"`, 1),
		strings.Replace(validManifest, `"integration_baseline_sha":"2222222222222222222222222222222222222222"`, `"integration_baseline_sha":"4444444444444444444444444444444444444444"`, 1),
	}
	for _, raw := range cases {
		next, err := Prepare([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if next.RequestDigest == first.RequestDigest {
			t.Fatal("scope or immutable input changed without digest change")
		}
	}
}
