package optimizationgate

import (
	"context"
	"crypto/ed25519"
	"errors"
)

type AttemptReconciliation string

const (
	AttemptPending  AttemptReconciliation = "PENDING"
	AttemptExpired  AttemptReconciliation = "EXPIRED"
	AttemptConsumed AttemptReconciliation = "CONSUMED_MATCHING"
)

var ErrAttemptConflict = errors.New("attempt already consumed with different evidence")

// ReconcileReviewAttempt is an intentionally read-only RED baseline.
// Its placeholder return value must fail the PostgreSQL integration tests.
// It never authorizes execution, releases resources or promotes a version.
func (s *AttemptStore) ReconcileReviewAttempt(
	ctx context.Context, trusted BaselinePolicy, signedReceipt []byte,
	keys map[string]ed25519.PublicKey, reader EvidenceReader,
) (AttemptReconciliation, error) {
	if ctx == nil || s == nil || s.pool == nil {
		return "", ErrAttemptUnconfigured
	}
	_, err := VerifyReviewEvidenceWithAssets(ctx, trusted, signedReceipt, keys, reader)
	if err != nil {
		return "", err
	}
	return AttemptPending, nil
}
