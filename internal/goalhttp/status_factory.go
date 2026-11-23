package goalhttp

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/admission"
	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

// NewCatalogGoalStatusLookup constructs an independent request-scoped,
// read-only ACL lookup. It re-introspects the bearer on every status call,
// requires the existing admission scope, and uses no public GitHub source
// inspection or issue mutation. Query outcome never authorizes a retry.
func NewCatalogGoalStatusLookup(repo *runpg.Repository, auth *admission.Introspector) (GoalStatusLookup, error) {
	if !configured(repo) || !configured(auth) {
		return nil, admission.ErrInvalidConfig
	}
	return func(ctx context.Context, bearer string, proposal issuegoal.Prepared) (runintent.Intent, error) {
		if ctx.Err() != nil {
			return runintent.Intent{}, ctx.Err()
		}
		if bearer == "" {
			return runintent.Intent{}, admission.ErrUnauthenticated
		}
		id, err := auth.Authenticate(ctx, bearer)
		if err != nil {
			return runintent.Intent{}, err
		}
		// Inspect is deliberately scoped to tokens allowed to submit the
		// same request. A distinct read-only OAuth scope needs a separate
		// security review before it may be introduced.
		authorized := false
		for _, scope := range strings.Split(id.Scope, " ") {
			if scope == admission.RunIntentCreateScope {
				authorized = true
				break
			}
		}
		if !authorized || id.ClientID == "" {
			return runintent.Intent{}, admission.ErrPolicyDenied
		}
		if !id.ExpiresAt.After(time.Now()) {
			return runintent.Intent{}, admission.ErrUnauthenticated
		}
		selector := runintent.Intent{
			ID: "validation-only", PrincipalID: "validation-only",
			TenantID: proposal.Target.TenantID, ProjectID: proposal.Target.ProjectID,
			AgentID: proposal.Target.AgentID, ReleaseID: proposal.Target.ReleaseID,
			SessionID: proposal.Target.SessionID, IdempotencyKey: proposal.IdempotencyKey,
			RequestDigest: proposal.RequestDigest, Status: runintent.Pending, Version: 1,
		}
		record, err := repo.LookupCatalogGoal(ctx, selector, runpg.CatalogClaims{
			Issuer: id.Issuer, Subject: id.Subject, ClientID: id.ClientID, ExpiresAt: id.ExpiresAt,
		})
		if errors.Is(err, runpg.ErrCatalogDenied) {
			return runintent.Intent{}, runpg.ErrNotFound
		}
		return record, err
	}, nil
}
