package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	"github.com/jackc/pgx/v5"
)

var (
	ErrCatalogDenied      = errors.New("admission catalog denied current identity or resource")
	ErrCatalogUnavailable = errors.New("admission catalog unavailable")
)

// CatalogClaims are trusted direct OAuth identity evidence, never client JSON.
// The admission layer must authenticate the token and verify its exact scope
// before calling this internal repository boundary.
type CatalogClaims struct {
	Issuer    string
	Subject   string
	ClientID  string
	ExpiresAt time.Time
}

type CatalogAuthorization struct {
	PrincipalID string
	Snapshot    runintent.PrincipalSnapshot
}

type catalogQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// One joined predicate supplies RBAC and ABAC from authoritative resources:
// active tenant/project/identity, RUNNER membership for this OAuth client,
// active release scoped to project+Agent, active session bound to release,
// and principal ownership. No user-provided role or snapshot is trusted.
const catalogQuery = `
	SELECT i.principal_id, i.subject_id, p.policy_revision, r.config_digest
	FROM admission_tenants t
	JOIN admission_projects p ON p.tenant_id=t.tenant_id
	JOIN admission_principals i ON i.tenant_id=t.tenant_id
	JOIN admission_memberships m ON m.tenant_id=i.tenant_id
	  AND m.principal_id=i.principal_id AND m.project_id=p.project_id
	JOIN admission_releases r ON r.tenant_id=p.tenant_id AND r.project_id=p.project_id
	JOIN admission_sessions s ON s.tenant_id=r.tenant_id AND s.project_id=r.project_id
	  AND s.agent_id=r.agent_id AND s.release_id=r.release_id
	  AND s.owner_principal_id=i.principal_id
	WHERE t.tenant_id=$1 AND p.project_id=$2 AND r.agent_id=$3 AND r.release_id=$4
	  AND s.session_id=$5 AND i.issuer=$6 AND i.external_subject=$7 AND m.client_id=$8
	  AND t.enabled AND p.enabled AND i.enabled AND m.enabled AND r.enabled AND s.enabled
	  AND m.role='RUNNER' AND $9::timestamptz > clock_timestamp()
`

func resolveCatalogAuthorization(ctx context.Context, q catalogQuerier, intent runintent.Intent, claims CatalogClaims, lock bool) (CatalogAuthorization, error) {
	var binding CatalogAuthorization
	if claims.Issuer == "" || claims.Subject == "" || claims.ClientID == "" || claims.ExpiresAt.IsZero() {
		return binding, ErrCatalogDenied
	}
	query := catalogQuery
	if lock {
		// Serialize admission against revocation or attribute updates.
		// Hold these row locks through the RunIntent/Outbox commit.
		query += " FOR SHARE OF t,p,i,m,r,s"
	}
	binding.Snapshot.Version = runintent.PrincipalSnapshotVersion
	binding.Snapshot.ProjectID = intent.ProjectID
	err := q.QueryRow(ctx, query, intent.TenantID, intent.ProjectID, intent.AgentID, intent.ReleaseID,
		intent.SessionID, claims.Issuer, claims.Subject, claims.ClientID, claims.ExpiresAt).Scan(
		&binding.PrincipalID, &binding.Snapshot.SubjectID, &binding.Snapshot.PolicyRevision, &binding.Snapshot.ConfigDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return CatalogAuthorization{}, ErrCatalogDenied
	}
	if err != nil {
		return CatalogAuthorization{}, ErrCatalogUnavailable
	}
	if lock {
		// A token may expire while waiting on an authority row lock.
		var stillActive bool
		if err := q.QueryRow(ctx, "SELECT clock_timestamp() < $1::timestamptz", claims.ExpiresAt).Scan(&stillActive); err != nil {
			return CatalogAuthorization{}, ErrCatalogUnavailable
		}
		if !stillActive {
			return CatalogAuthorization{}, ErrCatalogDenied
		}
	}
	binding.Snapshot.ActorID = binding.Snapshot.SubjectID
	candidate := intent
	candidate.PrincipalID = binding.PrincipalID
	candidate.PrincipalSnapshot = binding.Snapshot
	if candidate.Validate() != nil || binding.Snapshot.ValidateForProject(intent.ProjectID) != nil {
		return CatalogAuthorization{}, ErrCatalogDenied
	}
	return binding, nil
}

// ResolveCatalogAuthorization is a point-in-time decision. It is not enough
// for persistence; the exact decision is re-read and locked in CreateWithCatalog.
func (r *Repository) ResolveCatalogAuthorization(ctx context.Context, intent runintent.Intent, claims CatalogClaims) (CatalogAuthorization, error) {
	if r == nil || r.pool == nil {
		return CatalogAuthorization{}, ErrCatalogUnavailable
	}
	return resolveCatalogAuthorization(ctx, r.pool, intent, claims, false)
}

// CreateWithCatalog re-evaluates current catalog authority under row locks in
// the existing atomic creation transaction, even on idempotent replays.
// Legacy and exact-policy development entrypoints remain separate.
func (r *Repository) CreateWithCatalog(ctx context.Context, intent runintent.Intent, event Event, raw []byte, claims CatalogClaims) (runintent.Intent, bool, error) {
	if len(raw) > runintent.MaxExecutionInputBytes {
		return runintent.Intent{}, false, runintent.ErrInvalidExecutionInput
	}
	input := bytes.Clone(raw)
	if err := runintent.VerifyExecutionInput(intent, input); err != nil {
		return runintent.Intent{}, false, err
	}
	return r.create(ctx, intent, event, nil, input, &claims)
}
