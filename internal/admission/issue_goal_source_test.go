package admission

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

const sourceIssue = "https://github.com/example/repository/issues/123"

type fakeSource struct {
	readCalls     int
	baselineCalls int
	issue         issuegoal.GitHubIssueSnapshot
	baselines     issuegoal.PublicBaselineInspection
	readErr       error
	baselineErr   error
}

func (f *fakeSource) Read(_ context.Context, got string) (issuegoal.GitHubIssueSnapshot, error) {
	f.readCalls++
	if got != sourceIssue {
		return issuegoal.GitHubIssueSnapshot{}, errors.New("wrong issue URL")
	}
	return f.issue, f.readErr
}
func (f *fakeSource) InspectBaselines(_ context.Context, url, branch, experiment, integration string) (issuegoal.PublicBaselineInspection, error) {
	f.baselineCalls++
	if url != sourceIssue || branch != "main" || experiment != strings.Repeat("1", 40) || integration != strings.Repeat("2", 40) {
		return issuegoal.PublicBaselineInspection{}, errors.New("wrong SHA or branch selectors")
	}
	return f.baselines, f.baselineErr
}
func fixtureGoalSource() (TrustedGitHubIssuePolicy, issuegoal.Input, *fakeSource) {
	t := Target{TenantID: "t", ProjectID: "p", AgentID: "a", ReleaseID: "r", SessionID: "s"}
	input := issuegoal.Input{Kind: issuegoal.InputKind, IssueURL: sourceIssue, IssueSnapshotDigest: "sha256:" + strings.Repeat("4", 64), TargetBranch: "main", ExperimentBaselineSHA: strings.Repeat("1", 40), IntegrationBaselineSHA: strings.Repeat("2", 40), AcceptanceRulesDigest: "sha256:" + strings.Repeat("3", 64), Budget: issuegoal.Budget{MaxTokens: 2000, MaxRuntimeSeconds: 600, MaxSandboxSeconds: 300}}
	policy := TrustedGitHubIssuePolicy{Target: t, Repository: "example/repository", TargetBranch: "main", AcceptanceRulesDigest: input.AcceptanceRulesDigest, MaxBudget: issuegoal.Budget{MaxTokens: 3000, MaxRuntimeSeconds: 900, MaxSandboxSeconds: 500}}
	source := &fakeSource{
		issue:     issuegoal.GitHubIssueSnapshot{Schema: issuegoal.IssueSnapshotVersion, IssueURL: sourceIssue, IssueID: 1009, Number: 123, State: "open", Digest: input.IssueSnapshotDigest},
		baselines: issuegoal.PublicBaselineInspection{Schema: issuegoal.PublicBaselineInspectionVersion, IssueURL: sourceIssue, TargetBranch: "main", ExperimentBaselineSHA: input.ExperimentBaselineSHA, IntegrationBaselineSHA: input.IntegrationBaselineSHA, ObservedBranchHeadSHA: input.IntegrationBaselineSHA},
	}
	return policy, input, source
}

func TestTrustedIssueVerifierRequiresPolicyBeforeExternalRead(t *testing.T) {
	policy, input, source := fixtureGoalSource()
	verifier, err := NewTrustedGitHubIssueVerifier(source, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyIssueGoal(context.Background(), policy.Target, input); err != nil {
		t.Fatal(err)
	}
	if source.readCalls != 1 || source.baselineCalls != 1 {
		t.Fatalf("expected two source reads, got %d %d", source.readCalls, source.baselineCalls)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*TrustedGitHubIssuePolicy, *issuegoal.Input, *Target)
	}{
		{"different tenant", func(_ *TrustedGitHubIssuePolicy, _ *issuegoal.Input, t *Target) { t.TenantID = "another" }},
		{"cross repository", func(_ *TrustedGitHubIssuePolicy, i *issuegoal.Input, _ *Target) {
			i.IssueURL = "https://github.com/other/repo/issues/123"
		}},
		{"different branch", func(_ *TrustedGitHubIssuePolicy, i *issuegoal.Input, _ *Target) { i.TargetBranch = "feature" }},
		{"different rules", func(_ *TrustedGitHubIssuePolicy, i *issuegoal.Input, _ *Target) {
			i.AcceptanceRulesDigest = "sha256:" + strings.Repeat("5", 64)
		}},
		{"too many tokens", func(_ *TrustedGitHubIssuePolicy, i *issuegoal.Input, _ *Target) { i.Budget.MaxTokens = 3001 }},
		{"too long runtime", func(_ *TrustedGitHubIssuePolicy, i *issuegoal.Input, _ *Target) { i.Budget.MaxRuntimeSeconds = 901 }},
		{"too long sandbox", func(_ *TrustedGitHubIssuePolicy, i *issuegoal.Input, _ *Target) { i.Budget.MaxSandboxSeconds = 501 }},
		{"invalid kind", func(_ *TrustedGitHubIssuePolicy, i *issuegoal.Input, _ *Target) { i.Kind = "arbitrary" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, in, f := fixtureGoalSource()
			actualTarget := p.Target
			tc.mutate(&p, &in, &actualTarget)
			v, err := NewTrustedGitHubIssueVerifier(f, p)
			if err != nil {
				t.Fatal(err)
			}
			err = v.VerifyIssueGoal(context.Background(), actualTarget, in)
			if !errors.Is(err, ErrIssueGoalSourceDenied) || f.readCalls != 0 || f.baselineCalls != 0 {
				t.Fatalf("unauthorized input reached provider: %v reads=%d baseline=%d", err, f.readCalls, f.baselineCalls)
			}
		})
	}
}

func TestTrustedIssueVerifierFailsClosedOnChangedSourceAndIndeterminateReads(t *testing.T) {
	for _, tc := range []struct {
		name             string
		change           func(*fakeSource, *TrustedGitHubIssuePolicy)
		reads, baselines int
	}{
		{"issue changed", func(f *fakeSource, _ *TrustedGitHubIssuePolicy) { f.issue.Digest = "sha256:" + strings.Repeat("5", 64) }, 1, 0},
		{"issue identity spoof", func(f *fakeSource, _ *TrustedGitHubIssuePolicy) { f.issue.IssueID = 0 }, 1, 0},
		{"issue source unavailable", func(f *fakeSource, _ *TrustedGitHubIssuePolicy) { f.readErr = errors.New("rate limit") }, 1, 0},
		{"branch moved", func(f *fakeSource, _ *TrustedGitHubIssuePolicy) {
			f.baselines.ObservedBranchHeadSHA = strings.Repeat("1", 40)
		}, 1, 1},
		{"wrong baseline proof", func(f *fakeSource, _ *TrustedGitHubIssuePolicy) {
			f.baselines.ExperimentBaselineSHA = strings.Repeat("5", 40)
		}, 1, 1},
		{"branch no longer protected", func(f *fakeSource, p *TrustedGitHubIssuePolicy) { p.RequireProtectedBranch = true }, 1, 1},
		{"commit source unavailable", func(f *fakeSource, _ *TrustedGitHubIssuePolicy) { f.baselineErr = errors.New("missing commit") }, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, in, f := fixtureGoalSource()
			tc.change(f, &p)
			v, err := NewTrustedGitHubIssueVerifier(f, p)
			if err != nil {
				t.Fatal(err)
			}
			err = v.VerifyIssueGoal(context.Background(), p.Target, in)
			if !errors.Is(err, ErrIssueGoalSourceUnverified) || f.readCalls != tc.reads || f.baselineCalls != tc.baselines {
				t.Fatalf("unchecked/unavailable source accepted: err=%v issue=%d baseline=%d", err, f.readCalls, f.baselineCalls)
			}
		})
	}
}

func TestTrustedIssueVerifierFailsClosedOnInvalidConfigAndContext(t *testing.T) {
	p, in, f := fixtureGoalSource()
	var typedNil *fakeSource
	if _, err := NewTrustedGitHubIssueVerifier(typedNil, p); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("typed nil accepted: %v", err)
	}
	for _, change := range []func(*TrustedGitHubIssuePolicy){
		func(p *TrustedGitHubIssuePolicy) { p.Repository = "example/../repository" },
		func(p *TrustedGitHubIssuePolicy) { p.TargetBranch = "../main" },
		func(p *TrustedGitHubIssuePolicy) { p.AcceptanceRulesDigest = "sha256:NOT_HEX" },
		func(p *TrustedGitHubIssuePolicy) { p.MaxBudget.MaxTokens = 0 },
		func(p *TrustedGitHubIssuePolicy) { p.Target.TenantID = "" },
	} {
		modified := p
		change(&modified)
		if _, err := NewTrustedGitHubIssueVerifier(f, modified); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("invalid trusted policy accepted: %#v %v", modified, err)
		}
	}
	v, err := NewTrustedGitHubIssueVerifier(f, p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v.VerifyIssueGoal(ctx, p.Target, in); !errors.Is(err, context.Canceled) || f.readCalls != 0 {
		t.Fatalf("canceled call reached source: %v", err)
	}
}
