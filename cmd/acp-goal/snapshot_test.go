package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

type fakePublicIssue struct {
	calls  int
	result issuegoal.GitHubIssueSnapshot
	err    error
}

func (f *fakePublicIssue) Read(_ context.Context, url string) (issuegoal.GitHubIssueSnapshot, error) {
	f.calls++
	if url != "https://github.com/acme/example/issues/123" {
		return issuegoal.GitHubIssueSnapshot{}, errors.New("wrong issue URL")
	}
	return f.result, f.err
}

func TestSnapshotCLIEmitsDigestButNotUntrustedIssueBody(t *testing.T) {
	reader := &fakePublicIssue{result: issuegoal.GitHubIssueSnapshot{
		Schema: issuegoal.IssueSnapshotVersion, IssueURL: "https://github.com/acme/example/issues/123",
		IssueID: 98765, Number: 123, Title: "Untrusted title",
		Body: "hidden untrusted contents", Digest: "sha256:" + strings.Repeat("a", 64),
		UpdatedAt: "2026-11-21T01:00:00Z",
	}}
	var out, diagnostics bytes.Buffer
	err := runWithIssueReader([]string{"snapshot", "--issue-url", "https://github.com/acme/example/issues/123"},
		strings.NewReader(""), &out, &diagnostics, reader)
	if err != nil {
		t.Fatal(err)
	}
	if reader.calls != 1 || bytes.Contains(out.Bytes(), []byte("hidden untrusted contents")) {
		t.Fatalf("unsafe snapshot output or source calls: %s", out.String())
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["issue_snapshot_digest"] != "sha256:"+strings.Repeat("a", 64) ||
		result["issue_url"] != reader.result.IssueURL {
		t.Fatalf("incorrect CLI output: %s", out.String())
	}
}

func TestSnapshotCLIRejectsBadArgsWithoutNetwork(t *testing.T) {
	for _, args := range [][]string{
		{"snapshot"},
		{"snapshot", "--issue-url", "foo"},
		{"snapshot", "--issue-url", "foo", "extra"},
	} {
		reader := &fakePublicIssue{}
		var out, diagnostics bytes.Buffer
		if err := runWithIssueReader(args, strings.NewReader(""), &out, &diagnostics, reader); err == nil {
			t.Fatalf("unsafe CLI invocation accepted: %v", args)
		}
		if reader.calls != 0 || out.Len() != 0 {
			t.Fatalf("bad args contacted network or produced output: %v", args)
		}
	}
}
