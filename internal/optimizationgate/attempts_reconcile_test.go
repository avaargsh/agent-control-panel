package optimizationgate

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func signedVariant(t *testing.T, wire []byte, modify func(*EvaluationReceipt)) []byte {
	t.Helper()
	var envelope SignedReceipt
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	var receipt EvaluationReceipt
	if err := json.Unmarshal(envelope.Payload, &receipt); err != nil {
		t.Fatal(err)
	}
	modify(&receipt)
	_, _, private, _ := fixture()
	return signed(receipt, private)
}

func TestPostgresReconcilePendingThenConsumedWithoutNewPermission(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	policy, wire, keys, assets := attemptFixture(t, store)
	reader := &countingAttemptEvidenceReader{testEvidenceReader: assets}
	state, err := store.ReconcileReviewAttempt(context.Background(), policy, wire, keys, reader)
	if err != nil || state != AttemptPending {
		t.Fatalf("fresh attempt must be pending, got %q: %v", state, err)
	}
	if reader.opens != 0 {
		t.Fatalf("pending reconciliation fetched raw evidence unnecessarily: opens=%d", reader.opens)
	}
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, assets); err != nil {
		t.Fatal(err)
	}
	reader.opens = 0
	state, err = store.ReconcileReviewAttempt(context.Background(), policy, wire, keys, reader)
	if err != nil || state != AttemptConsumed {
		t.Fatalf("accepted receipt not reconciled from PG: %q: %v", state, err)
	}
	if reader.opens != 2 {
		t.Fatalf("consumed matching reconciliation must recheck both raw evidence objects: opens=%d", reader.opens)
	}
	var rows int
	if err := pool.QueryRow(context.Background(),
		"SELECT count(*) FROM optimization_verification_attempts WHERE verification_nonce=$1 AND consumed_at IS NOT NULL",
		policy.VerificationNonce).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("reconciliation changed canonical consumption count: count=%d err=%v", rows, err)
	}
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, assets); !errors.Is(err, ErrAttemptUnavailable) {
		t.Fatalf("read-only reconciliation reopened a consumed attempt: %v", err)
	}
}

func TestPostgresReconcileNeverEquatesASecondValidSignedReceipt(t *testing.T) {
	store, _ := disposableAttemptStore(t)
	policy, wire, keys, assets := attemptFixture(t, store)
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, assets); err != nil {
		t.Fatal(err)
	}
	changed := signedVariant(t, wire, func(r *EvaluationReceipt) { r.CandidateDurationNS -= 100000 })
	if _, err := store.ReconcileReviewAttempt(context.Background(), policy, changed, keys, assets); !errors.Is(err, ErrAttemptConflict) {
		t.Fatalf("different signed result incorrectly reconciled: %v", err)
	}
	state, err := store.ReconcileReviewAttempt(context.Background(), policy, wire, keys, assets)
	if err != nil || state != AttemptConsumed {
		t.Fatalf("authentic original receipt lost its journal proof: %q %v", state, err)
	}
}

func TestPostgresReconcileRejectsUnissuedChallenge(t *testing.T) {
	store, _ := disposableAttemptStore(t)
	policy, wire, keys, assets := attemptFixture(t, store)
	reader := &countingAttemptEvidenceReader{testEvidenceReader: assets}
	other := policy
	other.VerificationNonce = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	signedOther := signedVariant(t, wire, func(r *EvaluationReceipt) { r.VerificationNonce = other.VerificationNonce })
	if _, err := store.ReconcileReviewAttempt(context.Background(), other, signedOther, keys, reader); !errors.Is(err, ErrAttemptUnavailable) {
		t.Fatalf("unissued but validly signed result was treated as issued: %v", err)
	}
	if reader.opens != 0 {
		t.Fatalf("unissued challenge caused external evidence fetch: opens=%d", reader.opens)
	}
}

func TestPostgresReconcileExpiredAttemptFromDatabaseClock(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	p, r, key, keys := fixture()
	p.VerificationNonce = ""
	issued, err := store.IssueReviewAttempt(context.Background(), p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r.VerificationNonce = issued.VerificationNonce
	baseline, candidate := []byte("baseline"), []byte("candidate")
	r.BaselineEvidenceDigest = evidenceSHA(baseline)
	r.CandidateEvidenceDigest = evidenceSHA(candidate)
	assets := &countingAttemptEvidenceReader{testEvidenceReader: testEvidenceReader{
		r.BaselineEvidenceDigest:  baseline,
		r.CandidateEvidenceDigest: candidate,
	}}
	if _, err := pool.Exec(context.Background(), "SELECT pg_sleep(1.1)"); err != nil {
		t.Fatal(err)
	}
	state, err := store.ReconcileReviewAttempt(context.Background(), issued, signed(r, key), keys, assets)
	if err != nil || state != AttemptExpired {
		t.Fatalf("expired challenge treated as pending/accepted: %q %v", state, err)
	}
	if assets.opens != 0 {
		t.Fatalf("expired challenge caused external evidence fetch: opens=%d", assets.opens)
	}
}

// A journal read failure must retain the underlying PostgreSQL error for
// callers that distinguish schema/transport failures with errors.As.
func TestPostgresReconcilePreservesJournalReadError(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	policy, wire, keys, assets := attemptFixture(t, store)
	if _, err := pool.Exec(context.Background(),
		"ALTER TABLE optimization_verification_attempts RENAME TO optimization_verification_attempts_missing"); err != nil {
		t.Fatalf("inject missing journal relation: %v", err)
	}
	_, err := store.ReconcileReviewAttempt(context.Background(), policy, wire, keys, assets)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
		t.Fatalf("reconciliation did not preserve PostgreSQL undefined-table error: pgErr=%v err=%v", pgErr, err)
	}
	if !errors.Is(err, ErrAttemptUnconfigured) {
		t.Fatalf("journal read failure lost fail-closed classification: %v", err)
	}
}
