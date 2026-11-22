package optimizationgate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrAttemptUnconfigured  = errors.New("trusted optimization attempt journal unavailable")
	ErrAttemptUnavailable   = errors.New("optimization attempt expired, mismatched or already consumed")
	ErrAttemptCommitUnknown = errors.New("optimization attempt commit outcome unknown: read-only reconciliation required")
)

// AttemptStore is an internal PostgreSQL-only adapter. Trusted host admission
// and policy authorization must happen BEFORE calling IssueReviewAttempt.
// It does not provide any public issue/verify route or release authority.
type AttemptStore struct {
	pool *pgxpool.Pool
	// beginConsume is an internal injection point for commit-outcome tests.
	// Production NewAttemptStore always uses pool.Begin until this is set.
	beginConsume func(context.Context) (pgx.Tx, error)
}

func NewAttemptStore(pool *pgxpool.Pool) *AttemptStore {
	return &AttemptStore{pool: pool}
}

// IssueReviewAttempt generates a cryptographically random nonce and records
// the immutable exact experiment policy before handing the challenge to a
// verifier. Callers cannot select or reuse a nonce. PostgreSQL server time
// (not the caller's clock) owns the expiration boundary.
func (s *AttemptStore) IssueReviewAttempt(ctx context.Context, trusted BaselinePolicy, ttl time.Duration) (BaselinePolicy, error) {
	if ctx == nil || s == nil || s.pool == nil {
		return BaselinePolicy{}, ErrAttemptUnconfigured
	}
	if trusted.VerificationNonce != "" || ttl < time.Second || ttl > 24*time.Hour || ttl%time.Second != 0 {
		return BaselinePolicy{}, ErrInvalidContract
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return BaselinePolicy{}, fmt.Errorf("%w: generate nonce: %w", ErrAttemptUnconfigured, err)
	}
	trusted.VerificationNonce = hex.EncodeToString(nonce)
	if !validPolicy(trusted) {
		return BaselinePolicy{}, ErrInvalidContract
	}
	digest, err := policySHA(trusted)
	if err != nil {
		return BaselinePolicy{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return BaselinePolicy{}, fmt.Errorf("%w: begin issue: %w", ErrAttemptUnconfigured, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := bindAttemptScope(ctx, tx, trusted); err != nil {
		return BaselinePolicy{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO optimization_verification_attempts
		(verification_nonce, tenant_id, project_id, experiment_id, policy_digest, expires_at)
		VALUES ($1,$2,$3,$4,$5,clock_timestamp()+($6::bigint*interval '1 second'))`,
		trusted.VerificationNonce, trusted.TenantID, trusted.ProjectID, trusted.ExperimentID, digest,
		int64(ttl/time.Second)); err != nil {
		return BaselinePolicy{}, fmt.Errorf("%w: persist attempt: %w", ErrAttemptUnconfigured, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return BaselinePolicy{}, fmt.Errorf("%w: commit attempt: %w", ErrAttemptUnconfigured, err)
	}
	return trusted, nil
}

// ConsumeReviewEvidence authenticates independent signed result AND raw
// evidence bytes, then atomically consumes the exact issued challenge.
// A matching duplicate never returns review eligibility. Unknown transaction
// outcome must be reconciled; never blindly retry protected downstream work.
func (s *AttemptStore) ConsumeReviewEvidence(
	ctx context.Context, trusted BaselinePolicy, signedReceipt []byte,
	keys map[string]ed25519.PublicKey, reader EvidenceReader,
) (EvaluationReceipt, error) {
	if ctx == nil || s == nil || s.pool == nil {
		return EvaluationReceipt{}, ErrAttemptUnconfigured
	}
	if err := ctx.Err(); err != nil {
		return EvaluationReceipt{}, err
	}
	// Verify the bounded signed claim before looking up the challenge, so
	// unsigned callers cannot probe whether a nonce was issued. Do not fetch
	// external evidence for a missing, expired or already-consumed attempt.
	if _, err := VerifyReviewEvidence(trusted, signedReceipt, keys); err != nil {
		return EvaluationReceipt{}, err
	}
	policyDigest, err := policySHA(trusted)
	if err != nil {
		return EvaluationReceipt{}, err
	}
	if err := s.preflightPendingAttempt(ctx, trusted, policyDigest); err != nil {
		return EvaluationReceipt{}, err
	}
	// The preflight is a resource guard only, not authorization: final
	// PostgreSQL UPDATE below still atomically fences concurrent consumers.
	receipt, err := VerifyReviewEvidenceWithAssets(ctx, trusted, signedReceipt, keys, reader)
	if err != nil {
		return EvaluationReceipt{}, err
	}
	receiptDigest := digestBytes(signedReceipt)
	begin := s.pool.Begin
	if s.beginConsume != nil {
		begin = s.beginConsume
	}
	tx, err := begin(ctx)
	if err != nil {
		return EvaluationReceipt{}, fmt.Errorf("%w: begin consume: %w", ErrAttemptUnconfigured, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := bindAttemptScope(ctx, tx, trusted); err != nil {
		return EvaluationReceipt{}, err
	}
	var claimedNonce string
	err = tx.QueryRow(ctx, `UPDATE optimization_verification_attempts SET
		consumed_at=clock_timestamp(), signed_receipt_digest=$6,
		baseline_evidence_digest=$7, candidate_evidence_digest=$8, verifier_run_id=$9
		WHERE verification_nonce=$1 AND tenant_id=$2 AND project_id=$3
		  AND experiment_id=$4 AND policy_digest=$5
		  AND consumed_at IS NULL AND expires_at > clock_timestamp()
		RETURNING verification_nonce`,
		trusted.VerificationNonce, trusted.TenantID, trusted.ProjectID, trusted.ExperimentID,
		policyDigest, receiptDigest, receipt.BaselineEvidenceDigest, receipt.CandidateEvidenceDigest,
		receipt.VerifierRunID).Scan(&claimedNonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return EvaluationReceipt{}, ErrAttemptUnavailable
	}
	if err != nil {
		return EvaluationReceipt{}, fmt.Errorf("%w: consume attempt: %w", ErrAttemptUnconfigured, err)
	}
	if claimedNonce != trusted.VerificationNonce {
		return EvaluationReceipt{}, ErrAttemptUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return EvaluationReceipt{}, fmt.Errorf("%w: commit consumption: %w", ErrAttemptCommitUnknown, err)
	}
	return receipt, nil
}

// preflightPendingAttempt prevents replays and forged/unissued challenges
// from imposing external evidence-store downloads. It deliberately takes no
// row lock; final UPDATE must still enforce the one-time authority and expiry.
func (s *AttemptStore) preflightPendingAttempt(ctx context.Context, policy BaselinePolicy, policyDigest string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("%w: begin nonce preflight: %w", ErrAttemptUnconfigured, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := bindAttemptScope(ctx, tx, policy); err != nil {
		return err
	}
	var pending bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM optimization_verification_attempts
		WHERE verification_nonce=$1 AND tenant_id=$2 AND project_id=$3
		  AND experiment_id=$4 AND policy_digest=$5
		  AND consumed_at IS NULL AND expires_at>clock_timestamp()
	)`, policy.VerificationNonce, policy.TenantID, policy.ProjectID,
		policy.ExperimentID, policyDigest).Scan(&pending); err != nil {
		return fmt.Errorf("%w: inspect pending attempt: %w", ErrAttemptUnconfigured, err)
	}
	if !pending {
		return ErrAttemptUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: commit nonce preflight: %w", ErrAttemptUnconfigured, err)
	}
	return nil
}

func bindAttemptScope(ctx context.Context, tx pgx.Tx, p BaselinePolicy) error {
	_, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true), set_config('app.project_id',$2,true)", p.TenantID, p.ProjectID)
	if err != nil {
		return fmt.Errorf("%w: bind trusted DB scope: %w", ErrAttemptUnconfigured, err)
	}
	return nil
}

func policySHA(policy BaselinePolicy) (string, error) {
	if !validPolicy(policy) {
		return "", ErrInvalidContract
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("%w: policy marshal: %w", ErrInvalidContract, err)
	}
	return digestBytes(raw), nil
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
