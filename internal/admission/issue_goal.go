package admission

import (
	"context"
	"errors"
	"fmt"
	"reflect"

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

// A typed nil function or pointer assigned to an interface is not equal to
// nil. Reject it before any admission work rather than panicking inside an
// absent verifier, resolver, or store.
func issueGoalDependencyConfigured(value any) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Func, reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan:
		return !v.IsNil()
	default:
		return true
	}
}

// AdmitPreparedIssueGoal is an INTERNAL, non-dispatch adapter. It validates
// every untrusted proposal byte and requires an independent trusted source
// verifier before calling the EXISTING authenticated RunIntent admission.
// The normal resolver must still authenticate/authorize on every replay;
// this method does not mint Run IDs, issue Guard Permits, or enable execution.
func (s *Service) AdmitPreparedIssueGoal(ctx context.Context, proposalJSON []byte, sources IssueGoalSourceVerifier) (runintent.Intent, bool, error) {
	if s == nil || !issueGoalDependencyConfigured(s.store) ||
		!issueGoalDependencyConfigured(s.resolver) || !issueGoalDependencyConfigured(sources) {
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
	// Probe the trusted OAuth/CatalogPolicy boundary BEFORE allowing a
	// caller-provided Issue URL to trigger outbound provider requests.
	// DecodePrepared already recomputed and bound the exact input digest;
	// only this internal package may assert inputBound after that check.
	request := Request{
		Target: target, IdempotencyKey: proposal.IdempotencyKey,
		RequestDigest: proposal.RequestDigest, inputBound: true,
	}
	preflight, err := s.resolver.Resolve(ctx, request)
	if err != nil {
		return runintent.Intent{}, false, err
	}
	if preflight.Target != request.Target || preflight.RequestDigest != request.RequestDigest {
		return runintent.Intent{}, false, ErrInvalidGrant
	}
	if err := preflight.Snapshot.ValidateForProject(target.ProjectID); err != nil {
		return runintent.Intent{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return runintent.Intent{}, false, err
	}
	// The source verifier owns fresh external observations; the caller
	// cannot inject a precomputed success or downgrade source failures.
	if err := sources.VerifyIssueGoal(ctx, target, input); err != nil {
		return runintent.Intent{}, false, fmt.Errorf("%w: %w", ErrIssueGoalSourceUnverified, err)
	}
	// AdmitWithInput intentionally repeats authentication and authorization
	// after provider IO. The PostgreSQL CreateWithCatalog path still
	// rechecks current catalog authority under row locks at write time.
	// Never reuse a preflight Grant as persistent authority.
	if err := ctx.Err(); err != nil {
		return runintent.Intent{}, false, err
	}
	return s.AdmitWithInput(ctx, request, exact)
}
