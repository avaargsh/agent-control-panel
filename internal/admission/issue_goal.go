package admission

import (
	"context"
	"errors"
	"fmt"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

// IssueGoalSourceVerifier is supplied by the trusted ACP host, never by the
// incoming proposal. It must independently inspect the Issue snapshot,
// repository and pinned commits, rule bytes/signature, and budget ceiling.
// This package does not provide a permissive default implementation.
type IssueGoalSourceVerifier interface {
	VerifyIssueGoal(context.Context, Target, issuegoal.Input) error
}

var ErrIssueGoalSourceUnverified = errors.New("issue goal source could not be verified")

// AdmitPreparedIssueGoal is an INTERNAL, non-dispatch adapter. It validates
// every untrusted proposal byte and requires an independent trusted source
// verifier before calling the EXISTING authenticated RunIntent admission.
// The normal resolver must still authenticate/authorize on every replay;
// this method does not mint Run IDs, issue Guard Permits, or enable execution.
func (s *Service) AdmitPreparedIssueGoal(ctx context.Context, proposalJSON []byte, sources IssueGoalSourceVerifier) (runintent.Intent, bool, error) {
	if s == nil || s.store == nil || s.resolver == nil || sources == nil {
		return runintent.Intent{}, false, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return runintent.Intent{}, false, err
	}
	proposal, input, exact, err := issuegoal.DecodePrepared(proposalJSON)
	if err != nil {
		return runintent.Intent{}, false, err
	}
	target := Target{
		TenantID:  proposal.Target.TenantID,
		ProjectID: proposal.Target.ProjectID,
		AgentID:   proposal.Target.AgentID,
		ReleaseID: proposal.Target.ReleaseID,
		SessionID: proposal.Target.SessionID,
	}
	// The source verifier owns fresh external observations; the caller
	// cannot inject a precomputed success or downgrade source failures.
	if err := sources.VerifyIssueGoal(ctx, target, input); err != nil {
		return runintent.Intent{}, false, fmt.Errorf("%w: %w", ErrIssueGoalSourceUnverified, err)
	}
	if err := ctx.Err(); err != nil {
		return runintent.Intent{}, false, err
	}
	return s.AdmitWithInput(ctx, Request{
		Target: target, IdempotencyKey: proposal.IdempotencyKey,
		RequestDigest: proposal.RequestDigest,
	}, exact)
}
