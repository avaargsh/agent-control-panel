package admission

import (
	"context"
	"errors"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

type catalogReader interface {
	ResolveCatalogAuthorization(context.Context, runintent.Intent, runpg.CatalogClaims) (runpg.CatalogAuthorization, error)
}

type catalogInputStore interface {
	CreateWithCatalog(context.Context, runintent.Intent, runpg.Event, []byte, runpg.CatalogClaims) (runintent.Intent, bool, error)
}

// CatalogPolicy resolves direct OAuth identity against the current ACP-owned
// relational resource authority. It never authorizes protected side effects.
type CatalogPolicy struct {
	reader catalogReader
}

func NewCatalogPolicy(reader catalogReader) (*CatalogPolicy, error) {
	if reader == nil {
		return nil, ErrPolicyConfig
	}
	return &CatalogPolicy{reader: reader}, nil
}

func (p *CatalogPolicy) Authorize(ctx context.Context, id Identity, req Request) (Grant, error) {
	if p == nil || p.reader == nil {
		return Grant{}, ErrPolicyUnavailable
	}
	if !id.ExpiresAt.After(time.Now()) {
		return Grant{}, ErrUnauthenticated
	}
	if !req.inputBound || !hasCreateScope(id.Scope) ||
		!validHTTPS(id.Issuer) || !validIdentityValue(id.Subject) || !validIdentityValue(id.ClientID) {
		return Grant{}, ErrPolicyDenied
	}
	intent := runintent.Intent{
		ID: "validation-only", PrincipalID: "validation-only",
		TenantID: req.Target.TenantID, ProjectID: req.Target.ProjectID,
		AgentID: req.Target.AgentID, ReleaseID: req.Target.ReleaseID,
		SessionID: req.Target.SessionID, IdempotencyKey: req.IdempotencyKey,
		RequestDigest: req.RequestDigest, Status: runintent.Pending, Version: 1,
	}
	if err := intent.Validate(); err != nil {
		return Grant{}, err
	}
	claims := runpg.CatalogClaims{
		Issuer: id.Issuer, Subject: id.Subject, ClientID: id.ClientID, ExpiresAt: id.ExpiresAt,
	}
	authorized, err := p.reader.ResolveCatalogAuthorization(ctx, intent, claims)
	if errors.Is(err, runpg.ErrCatalogDenied) {
		return Grant{}, ErrPolicyDenied
	}
	if err != nil {
		return Grant{}, ErrPolicyUnavailable
	}
	return Grant{
		Target: req.Target, RequestDigest: req.RequestDigest,
		PrincipalID: authorized.PrincipalID, Snapshot: authorized.Snapshot,
		catalogClaims: &claims,
	}, nil
}

var _ PolicyAuthority = (*CatalogPolicy)(nil)
