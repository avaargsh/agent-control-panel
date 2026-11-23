package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	"github.com/jackc/pgx/v5"
)

// LookupCatalogGoal is a read-only, one-statement lookup of the original
// RunIntent under live ACP Catalog authority. The selector is an untrusted
// immutable request identity; claims must originate from validated OAuth
// introspection. Neither a missing result nor a revoked catalog grant proves
// that the original HTTP admission did not commit.
func (r *Repository) LookupCatalogGoal(ctx context.Context, selector runintent.Intent, claims CatalogClaims) (runintent.Intent, error) {
	if r == nil || r.pool == nil {
		return runintent.Intent{}, ErrCatalogUnavailable
	}
	if claims.Issuer == "" || claims.Subject == "" || claims.ClientID == "" ||
		claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(time.Now()) {
		return runintent.Intent{}, ErrCatalogDenied
	}
	if err := selector.Validate(); err != nil || selector.Status != runintent.Pending ||
		selector.Version != 1 {
		return runintent.Intent{}, ErrCatalogDenied
	}

	// The existing ACL binds the verified token to currently enabled
	// tenant/project/principal, RUNNER membership, release and owned session.
	// It is evaluated in the SAME PostgreSQL statement as the intent read,
	// so revocation cannot be bypassed between a separate authz and SELECT.
	//
	// The stored admission issuer/subject/client must also exactly match
	// the caller; a token newly granted to the same principal is insufficient
	// to impersonate the historical admission origin.
	columns := "ri." + strings.ReplaceAll(selectIntentColumns, ", ", ", ri.")
	query := "SELECT " + columns + " FROM run_intents ri " +
		"JOIN (" + catalogQuery + ") acl ON acl.principal_id=ri.principal_id " +
		"WHERE ri.tenant_id=$1 AND ri.project_id=$2 AND ri.agent_id=$3 " +
		"AND ri.release_id=$4 AND ri.session_id=$5 " +
		"AND ri.operation='" + operationCreate + "' " +
		"AND ri.admission_issuer=$6 AND ri.admission_external_subject=$7 " +
		"AND ri.admission_client_id=$8 " +
		"AND ri.idempotency_key=$10 AND ri.request_digest=$11"
	intent, err := scanIntent(r.pool.QueryRow(ctx, query,
		selector.TenantID, selector.ProjectID, selector.AgentID,
		selector.ReleaseID, selector.SessionID,
		claims.Issuer, claims.Subject, claims.ClientID, claims.ExpiresAt,
		selector.IdempotencyKey, selector.RequestDigest,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return runintent.Intent{}, ErrNotFound
	}
	if err != nil {
		return runintent.Intent{}, ErrCatalogUnavailable
	}
	if intent.TenantID != selector.TenantID || intent.ProjectID != selector.ProjectID ||
		intent.AgentID != selector.AgentID || intent.ReleaseID != selector.ReleaseID ||
		intent.SessionID != selector.SessionID || intent.IdempotencyKey != selector.IdempotencyKey ||
		intent.RequestDigest != selector.RequestDigest {
		return runintent.Intent{}, ErrCatalogUnavailable
	}
	return intent, nil
}
