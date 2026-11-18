package postgres

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	"github.com/jackc/pgx/v5"
)

var executionAuthorityID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var executionAuthoritySchema = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// ExecutionAuthorityRef identifies an already accepted Run, not a new
// admission request. Caller identity must be independently authenticated at
// the service boundary, before using this internal repository method.
type ExecutionAuthorityRef struct {
	TenantID      string
	RunIntentID   string
	RequestDigest string
	RunID         string
}

// ExecutionAuthority is a current ACP catalog observation. It does not
// authorize model egress or a protected effect, attest context/evidence,
// refresh an OAuth token, or establish Runtime lifecycle safety.
type ExecutionAuthority struct {
	Ref         ExecutionAuthorityRef
	PrincipalID string
	AgentID     string
	ReleaseID   string
	SessionID   string
	Snapshot    runintent.PrincipalSnapshot
}

// GetExecutionAuthority rechecks the exact original OAuth client membership
// and all admitted resource attributes in one PostgreSQL snapshot. It never
// substitutes a different client or uses a legacy principal-only assertion.
// OAuth access token expiry is not a durable Run lease; current IdP session
// revocation requires a separate issuer-owned revocation feed/contract.
func (r *Repository) GetExecutionAuthority(ctx context.Context, ref ExecutionAuthorityRef) (ExecutionAuthority, error) {
	var empty ExecutionAuthority
	if r == nil || r.pool == nil {
		return empty, ErrCatalogUnavailable
	}
	if ref.TenantID == "" || len(ref.TenantID) > 255 || strings.TrimSpace(ref.TenantID) != ref.TenantID ||
		!executionAuthorityID.MatchString(ref.RunIntentID) || !executionAuthorityID.MatchString(ref.RunID) ||
		len(ref.RequestDigest) != 71 || !strings.HasPrefix(ref.RequestDigest, "sha256:") {
		return empty, ErrCatalogDenied
	}
	schema := r.pool.Config().ConnConfig.RuntimeParams["search_path"]
	if schema == "" {
		schema = "public"
	}
	if !executionAuthoritySchema.MatchString(schema) || strings.HasPrefix(schema, "pg_") || schema == "information_schema" {
		return empty, ErrCatalogUnavailable
	}
	table := func(name string) string {
		return pgx.Identifier{schema, name}.Sanitize()
	}
	// The identifiers are trusted configuration, not caller selectors.
	// Explicit qualification prevents temporary-table shadowing.
	query := fmt.Sprintf(`
		SELECT i.id::text,i.tenant_id,i.principal_id,i.project_id,i.agent_id,i.release_id,i.session_id,
		       i.idempotency_key,i.request_digest,i.principal_snapshot_version,
		       i.principal_subject_id,i.principal_actor_id,i.principal_policy_revision,
		       i.principal_config_digest,i.execution_input
		FROM %s i
		JOIN %s t ON t.tenant_id=i.tenant_id
		JOIN %s p ON p.tenant_id=i.tenant_id AND p.project_id=i.project_id
		JOIN %s u ON u.tenant_id=i.tenant_id AND u.principal_id=i.principal_id
		  AND u.issuer=i.admission_issuer AND u.external_subject=i.admission_external_subject
		JOIN %s m ON m.tenant_id=i.tenant_id AND m.project_id=i.project_id
		  AND m.principal_id=i.principal_id AND m.client_id=i.admission_client_id
		JOIN %s a ON a.tenant_id=i.tenant_id AND a.project_id=i.project_id
		  AND a.agent_id=i.agent_id AND a.release_id=i.release_id
		JOIN %s s ON s.tenant_id=i.tenant_id AND s.project_id=i.project_id
		  AND s.session_id=i.session_id AND s.agent_id=i.agent_id AND s.release_id=i.release_id
		  AND s.owner_principal_id=i.principal_id
		WHERE i.tenant_id=$1 AND i.id=$2::uuid AND i.request_digest=$3
		  AND i.runtime_run_id=$4 AND i.workflow_id='agent-run/v1/'||$4 AND i.status='ACCEPTED'
		  AND i.execution_input IS NOT NULL AND i.principal_snapshot_version='acp-principal/v1'
		  AND i.principal_subject_id=u.subject_id AND i.principal_actor_id=u.subject_id
		  AND i.principal_policy_revision=p.policy_revision AND i.principal_config_digest=a.config_digest
		  AND t.enabled AND p.enabled AND u.enabled AND m.enabled AND a.enabled AND s.enabled
		  AND m.role='RUNNER'
	`, table("run_intents"), table("admission_tenants"), table("admission_projects"),
		table("admission_principals"), table("admission_memberships"), table("admission_releases"), table("admission_sessions"))
	var i runintent.Intent
	var input []byte
	err := r.pool.QueryRow(ctx, query, ref.TenantID, ref.RunIntentID, ref.RequestDigest, ref.RunID).Scan(
		&i.ID, &i.TenantID, &i.PrincipalID, &i.ProjectID, &i.AgentID, &i.ReleaseID, &i.SessionID,
		&i.IdempotencyKey, &i.RequestDigest, &i.PrincipalSnapshot.Version,
		&i.PrincipalSnapshot.SubjectID, &i.PrincipalSnapshot.ActorID, &i.PrincipalSnapshot.PolicyRevision,
		&i.PrincipalSnapshot.ConfigDigest, &input)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, ErrCatalogDenied
	}
	if err != nil {
		return empty, ErrCatalogUnavailable
	}
	i.PrincipalSnapshot.ProjectID = i.ProjectID
	i.Version, i.Status, i.RunID, i.WorkflowID = 1, runintent.Accepted, ref.RunID, "agent-run/v1/"+ref.RunID
	if i.Validate() != nil || i.PrincipalSnapshot.ValidateForProject(i.ProjectID) != nil ||
		runintent.VerifyExecutionInput(i, input) != nil {
		return empty, ErrCatalogUnavailable
	}
	return ExecutionAuthority{
		Ref: ref, PrincipalID: i.PrincipalID, AgentID: i.AgentID, ReleaseID: i.ReleaseID,
		SessionID: i.SessionID, Snapshot: i.PrincipalSnapshot,
	}, nil
}
