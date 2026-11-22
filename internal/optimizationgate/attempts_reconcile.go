package optimizationgate

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// AttemptReconciliation is an observation only. None of these values grants
// execution, permits a release, allows a duplicate consumer or creates a PR.
type AttemptReconciliation string

const (
	AttemptPending  AttemptReconciliation = "PENDING"
	AttemptExpired  AttemptReconciliation = "EXPIRED"
	AttemptConsumed AttemptReconciliation = "CONSUMED_MATCHING"
)

var ErrAttemptConflict = errors.New("attempt already consumed with different evidence")

// ReconcileReviewAttempt is a read-only PostgreSQL inspection for uncertain
// commit outcomes. The caller must supply the same independently sourced
// pinned policy, verifier keys and original content-addressed raw evidence.
// A CONSUMED_MATCHING observation does NOT replay a review-eligibility permit;
// upstream must reconcile the idempotent action journal separately.
func (s *AttemptStore) ReconcileReviewAttempt(
	ctx context.Context, trusted BaselinePolicy, signedReceipt []byte,
	keys map[string]ed25519.PublicKey, reader EvidenceReader,
) (AttemptReconciliation, error) {
	if ctx == nil || s == nil || s.pool == nil {
		return "", ErrAttemptUnconfigured
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	receipt, err := VerifyReviewEvidenceWithAssets(ctx, trusted, signedReceipt, keys, reader)
	if err != nil {
		return "", err
	}
	digest, err := policySHA(trusted)
	if err != nil {
		return "", err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: begin read-only reconciliation: %v", ErrAttemptUnconfigured, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := bindAttemptScope(ctx, tx, trusted); err != nil {
		return "", err
	}
	var consumed pgtype.Timestamptz
	var expired bool
	var signedDigest, baselineDigest, candidateDigest, verifierRunID string
	err = tx.QueryRow(ctx, `SELECT consumed_at, expires_at <= clock_timestamp(),
		coalesce(signed_receipt_digest,''), coalesce(baseline_evidence_digest,''),
		coalesce(candidate_evidence_digest,''), coalesce(verifier_run_id,'')
		FROM optimization_verification_attempts
		WHERE verification_nonce=$1 AND tenant_id=$2 AND project_id=$3
		  AND experiment_id=$4 AND policy_digest=$5`,
		trusted.VerificationNonce, trusted.TenantID, trusted.ProjectID,
		trusted.ExperimentID, digest,
	).Scan(&consumed, &expired, &signedDigest, &baselineDigest, &candidateDigest, &verifierRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrAttemptUnavailable
	}
	if err != nil {
		return "", fmt.Errorf("%w: read attempt journal: %v", ErrAttemptUnconfigured, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("%w: commit read-only reconciliation: %v", ErrAttemptUnconfigured, err)
	}
	if !consumed.Valid {
		if expired {
			return AttemptExpired, nil
		}
		return AttemptPending, nil
	}
	if signedDigest != digestBytes(signedReceipt) ||
		baselineDigest != receipt.BaselineEvidenceDigest ||
		candidateDigest != receipt.CandidateEvidenceDigest ||
		verifierRunID != receipt.VerifierRunID {
		return "", ErrAttemptConflict
	}
	return AttemptConsumed, nil
}
