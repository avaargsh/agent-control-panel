package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// GetGuardRunAuthority resolves an accepted Run into its ACP-owned immutable
// RunIntent identity, and then reuses the existing full live catalog join.
// Guard supplies only tenant and Run; it cannot select an Intent, principal,
// OAuth client or policy. Result is a read-only observation, never a Permit.
//
// Concurrent catalog changes between the selector read and the full join
// still fail closed on the final verification. A subsequent revoke is not
// atomically fenced here; the execution PEP must revalidate separately.
func (r *Repository) GetGuardRunAuthority(ctx context.Context, tenantID, runID string) (ExecutionAuthority, []byte, error) {
	var empty ExecutionAuthority
	if r == nil || r.pool == nil {
		return empty, nil, ErrCatalogUnavailable
	}
	if tenantID == "" || len(tenantID) > 255 ||
		!executionAuthorityID.MatchString(runID) {
		return empty, nil, ErrCatalogDenied
	}
	schema := r.pool.Config().ConnConfig.RuntimeParams["search_path"]
	if schema == "" {
		schema = "public"
	}
	if !executionAuthoritySchema.MatchString(schema) ||
		schema == "information_schema" || len(schema) >= 3 && schema[:3] == "pg_" {
		return empty, nil, ErrCatalogUnavailable
	}
	table := pgx.Identifier{schema, "run_intents"}.Sanitize()
	// The admitted Run and its immutable request digest are read from ACP's
	// relational state, never from the untrusted Guard ActionSubmission.
	sql := fmt.Sprintf(`SELECT id::text,request_digest FROM %s
        WHERE tenant_id=$1 AND runtime_run_id=$2::uuid AND
              status='ACCEPTED' AND workflow_id='agent-run/v1/'||$2`, table)
	var intentID, digest string
	err := r.pool.QueryRow(ctx, sql, tenantID, runID).Scan(&intentID, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, nil, ErrCatalogDenied
	}
	if err != nil {
		return empty, nil, ErrCatalogUnavailable
	}
	if !executionAuthorityID.MatchString(intentID) || len(digest) != 71 || digest[:7] != "sha256:" {
		return empty, nil, ErrCatalogUnavailable
	}
	ref := ExecutionAuthorityRef{TenantID: tenantID, RunIntentID: intentID, RunID: runID, RequestDigest: digest}
	auth, raw, err := r.GetExecutionAuthorityInput(ctx, ref)
	if err != nil {
		return empty, nil, err
	}
	if auth.Ref != ref || auth.PrincipalID == "" || auth.ReleaseID == "" || auth.SessionID == "" {
		return empty, nil, ErrCatalogUnavailable
	}
	return auth, raw, nil
}
