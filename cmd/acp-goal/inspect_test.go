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

type fakeGoalInspectionSource struct {
	issueCalls    int
	baselineCalls int
	digest        string
	branchHead    string
}

func (f *fakeGoalInspectionSource) Read(_ context.Context, url string) (issuegoal.GitHubIssueSnapshot, error) {
	f.issueCalls++
	return issuegoal.GitHubIssueSnapshot{
		Schema: issuegoal.IssueSnapshotVersion, IssueURL: url,
		Digest: f.digest,
	}, nil
}

func (f *fakeGoalInspectionSource) InspectBaselines(_ context.Context, issueURL, branch, experiment, integration string) (issuegoal.PublicBaselineInspection, error) {
	f.baselineCalls++
	return issuegoal.PublicBaselineInspection{
		Schema: issuegoal.PublicBaselineInspectionVersion, IssueURL: issueURL,
		TargetBranch: branch, ExperimentBaselineSHA: experiment,
		IntegrationBaselineSHA: integration, ObservedBranchHeadSHA: f.branchHead,
	}, nil
}

func TestInspectCLIBindsPublicIssueAndBaselines(t *testing.T) {
	src := &fakeGoalInspectionSource{digest: "sha256:" + strings.Repeat("4", 64), branchHead: strings.Repeat("2", 40)}
	var out, diagnostic bytes.Buffer
	err := runWithIssueReader([]string{"inspect", "--file", "-"}, strings.NewReader(validManifest), &out, &diagnostic, src)
	if err != nil {
		t.Fatal(err)
	}
	if src.issueCalls != 1 || src.baselineCalls != 1 {
		t.Fatalf("unexpected source calls: %d/%d", src.issueCalls, src.baselineCalls)
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v["status"] != "public-source-observed-only" || v["request_digest"] == "" || v["integration_baseline_sha"] != strings.Repeat("2", 40) {
		t.Fatalf("incorrect observation: %s", out.String())
	}
	if strings.Contains(out.String(), "body") || strings.Contains(out.String(), "token") {
		t.Fatal("untrusted data/secret in output")
	}
}

func TestInspectCLIRejectsStaleSourcesBeforeOutput(t *testing.T) {
	for _, tc := range []struct {
		name          string
		digest, head  string
		want          error
		baselineCalls int
	}{
		{"changed issue", "sha256:" + strings.Repeat("5", 64), strings.Repeat("2", 40), issuegoal.ErrIssueSnapshotMismatch, 0},
		{"moved branch", "sha256:" + strings.Repeat("4", 64), strings.Repeat("1", 40), issuegoal.ErrBaselineMismatch, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakeGoalInspectionSource{digest: tc.digest, branchHead: tc.head}
			var out, diags bytes.Buffer
			err := runWithIssueReader([]string{"inspect", "--file", "-"}, strings.NewReader(validManifest), &out, &diags, src)
			if !errors.Is(err, tc.want) || out.Len() != 0 || src.baselineCalls != tc.baselineCalls {
				t.Fatalf("unsafe source accepted: err=%v output=%s calls=%d", err, out.String(), src.baselineCalls)
			}
		})
	}
}

func TestInspectCLIRejectsBadManifestWithoutSourceReads(t *testing.T) {
	src := &fakeGoalInspectionSource{digest: "sha256:" + strings.Repeat("4", 64), branchHead: strings.Repeat("2", 40)}
	var out, diags bytes.Buffer
	raw := strings.Replace(validManifest, `"target_branch":"main"`, `"target_branch":"../bad"`, 1)
	if err := runWithIssueReader([]string{"inspect", "--file", "-"}, strings.NewReader(raw), &out, &diags, src); err == nil || src.issueCalls != 0 || src.baselineCalls != 0 || out.Len() != 0 {
		t.Fatal("malformed manifest touched external source")
	}
}
