package admission

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

// GitHubGoalReader observes public Issue and pinned Git objects. Production
// hosts should inject the fixed-origin TLS reader from the issuegoal package.
// A test reader cannot substitute for production source evidence.
type GitHubGoalReader interface {
	Read(context.Context, string) (issuegoal.GitHubIssueSnapshot, error)
	InspectBaselines(context.Context, string, string, string, string) (issuegoal.PublicBaselineInspection, error)
}

// TrustedGitHubIssuePolicy is configured solely by the ACP host. It is an
// exact-scope allowlist, NOT a caller-controlled proposal, a signed ruleset,
// or actual runtime quota enforcement.
type TrustedGitHubIssuePolicy struct {
	Target                 Target
	Repository             string
	TargetBranch           string
	AcceptanceRulesDigest  string
	MaxBudget              issuegoal.Budget
	RequireProtectedBranch bool
}

var (
	ErrIssueGoalSourceDenied = errors.New("issue goal outside trusted source policy")
	digestPattern            = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// TrustedGitHubIssueVerifier checks configured scope/budgets BEFORE any
// provider read, then re-observes mutable public GitHub sources. Admission
// still requires an authenticated resolver before and after this call.
type TrustedGitHubIssueVerifier struct {
	reader GitHubGoalReader
	policy TrustedGitHubIssuePolicy
}

func NewTrustedGitHubIssueVerifier(reader GitHubGoalReader, policy TrustedGitHubIssuePolicy) (*TrustedGitHubIssueVerifier, error) {
	if !issueGoalDependencyConfigured(reader) || !validTrustedGitHubIssuePolicy(policy) {
		return nil, ErrInvalidConfig
	}
	return &TrustedGitHubIssueVerifier{reader: reader, policy: policy}, nil
}

func validTrustedGitHubIssuePolicy(p TrustedGitHubIssuePolicy) bool {
	t := p.Target
	if t.TenantID == "" || t.ProjectID == "" || t.AgentID == "" || t.ReleaseID == "" || t.SessionID == "" ||
		strings.TrimSpace(p.Repository) != p.Repository ||
		issuegoal.ValidateIssueURL("https://github.com/"+p.Repository+"/issues/1") != nil ||
		issuegoal.ValidateTargetBranch(p.TargetBranch) != nil ||
		!digestPattern.MatchString(p.AcceptanceRulesDigest) {
		return false
	}
	b := p.MaxBudget
	return b.MaxTokens > 0 && b.MaxTokens <= 10_000_000 &&
		b.MaxRuntimeSeconds > 0 && b.MaxRuntimeSeconds <= 86_400 &&
		b.MaxSandboxSeconds > 0 && b.MaxSandboxSeconds <= b.MaxRuntimeSeconds
}

// VerifyIssueGoal satisfies the existing ACP source verifier interface.
// A matching GitHub observation and operator allowlist is NOT independent
// rules-signature validation or authorization to execute the task.
func (v *TrustedGitHubIssueVerifier) VerifyIssueGoal(ctx context.Context, target Target, input issuegoal.Input) error {
	if v == nil || !issueGoalDependencyConfigured(v.reader) || !validTrustedGitHubIssuePolicy(v.policy) {
		return ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p := v.policy
	if target != p.Target || input.Kind != issuegoal.InputKind ||
		issuegoal.ValidateIssueURL(input.IssueURL) != nil ||
		issuegoal.ValidateTargetBranch(input.TargetBranch) != nil ||
		input.TargetBranch != p.TargetBranch ||
		input.AcceptanceRulesDigest != p.AcceptanceRulesDigest ||
		input.Budget.MaxTokens <= 0 || input.Budget.MaxTokens > p.MaxBudget.MaxTokens ||
		input.Budget.MaxRuntimeSeconds <= 0 || input.Budget.MaxRuntimeSeconds > p.MaxBudget.MaxRuntimeSeconds ||
		input.Budget.MaxSandboxSeconds <= 0 || input.Budget.MaxSandboxSeconds > p.MaxBudget.MaxSandboxSeconds ||
		input.Budget.MaxSandboxSeconds > input.Budget.MaxRuntimeSeconds {
		return ErrIssueGoalSourceDenied
	}
	parts := strings.Split(input.IssueURL, "/")
	if len(parts) != 7 || parts[3]+"/"+parts[4] != p.Repository ||
		!digestPattern.MatchString(input.IssueSnapshotDigest) ||
		!validLowerSHA(input.ExperimentBaselineSHA) || !validLowerSHA(input.IntegrationBaselineSHA) {
		return ErrIssueGoalSourceDenied
	}
	wantNumber, _ := strconv.ParseInt(parts[6], 10, 64)
	observed, err := v.reader.Read(ctx, input.IssueURL)
	if err != nil {
		return fmt.Errorf("%w: public Issue read: %w", ErrIssueGoalSourceUnverified, err)
	}
	if observed.Schema != issuegoal.IssueSnapshotVersion || observed.IssueURL != input.IssueURL ||
		observed.Number != wantNumber || observed.IssueID <= 0 || observed.State != "open" ||
		observed.Digest != input.IssueSnapshotDigest {
		return ErrIssueGoalSourceUnverified
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	baselines, err := v.reader.InspectBaselines(ctx, input.IssueURL, input.TargetBranch, input.ExperimentBaselineSHA, input.IntegrationBaselineSHA)
	if err != nil {
		return fmt.Errorf("%w: baseline observation: %w", ErrIssueGoalSourceUnverified, err)
	}
	if baselines.Schema != issuegoal.PublicBaselineInspectionVersion || baselines.IssueURL != input.IssueURL ||
		baselines.TargetBranch != input.TargetBranch ||
		baselines.ExperimentBaselineSHA != input.ExperimentBaselineSHA ||
		baselines.IntegrationBaselineSHA != input.IntegrationBaselineSHA ||
		baselines.ObservedBranchHeadSHA != input.IntegrationBaselineSHA ||
		(p.RequireProtectedBranch && !baselines.BranchProtected) {
		return ErrIssueGoalSourceUnverified
	}
	return ctx.Err()
}

func validLowerSHA(sha string) bool {
	if len(sha) != 40 {
		return false
	}
	for _, b := range sha {
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return false
		}
	}
	return true
}

var _ IssueGoalSourceVerifier = (*TrustedGitHubIssueVerifier)(nil)
