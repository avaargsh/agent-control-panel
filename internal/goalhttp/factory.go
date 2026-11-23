package goalhttp

import (
	"context"

	"github.com/avaargsh/agent-control-panel/internal/admission"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

// NewCatalogGoalServiceFactory composes existing ACP authorities for the
// opt-in, non-dispatch GoalSubmit handler. It does not create an HTTP listener,
// configure TLS, discover OAuth identity or enable runtime execution.
//
// The host must instantiate the Introspector through NewIntrospector with its
// validated issuer and trust roots and separately supply a trusted GitHub
// source verifier to NewHandler. Every invocation builds a fresh bearer-bound
// resolver; never cache the bearer or caller's authorization result.
func NewCatalogGoalServiceFactory(repo *runpg.Repository, auth *admission.Introspector) (GoalServiceFactory, error) {
	if !configured(repo) || !configured(auth) {
		return nil, admission.ErrInvalidConfig
	}
	policy, err := admission.NewCatalogPolicy(repo)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, bearer string) (GoalAdmitter, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if bearer == "" {
			return nil, admission.ErrUnauthenticated
		}
		return admission.New(repo, admission.NewBearerResolver(auth, policy, bearer)), nil
	}, nil
}
