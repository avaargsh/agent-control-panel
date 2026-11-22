package optimizationgate

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type AttemptReconciliation string

const (
	AttemptPending  AttemptReconciliation = "PENDING"
	AttemptExpired  AttemptReconciliation = "EXPIRED"
	AttemptConsumed AttemptReconciliation = "CONSUMED_MATCHING"
)

var ErrAttemptConflict = errors.New("attempt already consumed with different evidence")

// ReconcileReviewAttempt is intentionally a read-only placeholder for the
// RED integration commit: it must never be used to issue review eligibility.
// The PostgreSQL-bound implementation must replace this before acceptance.
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

// Verify that an operator-side inspection never upgrades a previously
// consumed attempt into an additional release or approval.
func reconcileAttemptNoop(_ context.Context, _ *pgxpool.Pool) error {
	return nil
}

func unmarshalEvaluationReceipt(t *testing.T, wire []byte) EvaluationReceipt {
	t.Helper()
	var envelope SignedReceipt
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	var receipt EvaluationReceipt
	if err := json.Unmarshal(envelope.Payload, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func copiedSignedReceipt(t *testing.T, wire []byte, edit func(*EvaluationReceipt)) []byte {
	t.Helper()
	r := unmarshalEvaluationReceipt(t, wire)
	edit(&r)
	_, _, private, _ := fixture()
	return signed(r, ed25519.PrivateKey(private))
}

// A typed result distinguishes an existing exact consumed receipt from an
// unknown/expired/mismatched attempt. None of these states grants a Permit.
func TestPostgresReconcilePendingThenConsumedOnlyOnce(t *testing.T) {
	store, _ := disposableAttemptStore(t)
	policy, wire, keys, reader := attemptFixture(t, store)
	state, err := store.ReconcileReviewAttempt(context.Background(), policy, wire, keys, reader)
	if err != nil || state != AttemptPending {
		t.Fatalf("issued fresh attempt should be PENDING: state=%s err=%v", state, err)
	}
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, reader); err != nil {
		t.Fatal(err)
	}
	state, err = store.ReconcileReviewAttempt(context.Background(), policy, wire, keys, reader)
	if err != nil || state != AttemptConsumed {
		t.Fatalf("exact consumed receipt should reconcile read-only: state=%s err=%v", state, err)
	}
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, reader); !errors.Is(err, ErrAttemptUnavailable) {
		t.Fatalf("reconciliation incorrectly re-enabled consumption: %v", err)
	}
}

func TestPostgresReconcileRejectsDifferentSignedReceiptAndUnissuedNonce(t *testing.T) {
	store, _ := disposableAttemptStore(t)
	policy, wire, keys, reader := attemptFixture(t, store)
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, reader); err != nil {
		t.Fatal(err)
	}
	changed := copiedSignedReceipt(t, wire, func(r *EvaluationReceipt) {
		r.CandidateDurationNS -= 100000
	})
	if _, err := store.ReconcileReviewAttempt(context.Background(), policy, changed, keys, reader); !errors.Is(err, ErrAttemptConflict) {
		t.Fatalf("different but valid signed receipt falsely reconciled: %v", err)
	}
	unknown := policy
	unknown.VerificationNonce = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	unknownWire := copiedSignedReceipt(t, wire, func(r *EvaluationReceipt) {
		r.VerificationNonce = unknown.VerificationNonce
	})
	if _, err := store.ReconcileReviewAttempt(context.Background(), unknown, unknownWire, keys, reader); !errors.Is(err, ErrAttemptUnavailable) {
		t.Fatalf("unissued nonce falsely reconciled: %v", err)
	}
}

func TestPostgresReconcileShowsExpiredWithoutConsuming(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	p, receipt, key, keys := fixture()
	p.VerificationNonce = ""
	issued, err := store.IssueReviewAttempt(context.Background(), p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	receipt.VerificationNonce = issued.VerificationNonce
	baseline, candidate := []byte("base"), []byte("candidate")
	receipt.BaselineEvidenceDigest = evidenceSHA(baseline)
	receipt.CandidateEvidenceDigest = evidenceSHA(candidate)
	reader := testEvidenceReader{
		receipt.BaselineEvidenceDigest:  baseline,
		receipt.CandidateEvidenceDigest: candidate,
	}
	if _, err := pool.Exec(context.Background(), "SELECT pg_sleep(1.1)"); err != nil {
		t.Fatal(err)
	}
	state, err := store.ReconcileReviewAttempt(context.Background(), issued, signed(receipt, key), keys, reader)
	if err != nil || state != AttemptExpired {
		t.Fatalf("expired challenge must not show fresh: state=%s err=%v", state, err)
	}
}
