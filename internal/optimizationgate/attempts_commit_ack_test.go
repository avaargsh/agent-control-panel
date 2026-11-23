package optimizationgate

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

var errInjectedCommitACKLoss = errors.New("test fault: committed but ACK lost")

// This fault adapter performs a real PostgreSQL COMMIT and then drops only
// the driver-visible acknowledgment. This proves the reconciliation contract
// without alleging a real TCP fault/packet-loss test.
type commitThenLoseACKTx struct{ pgx.Tx }

func (tx *commitThenLoseACKTx) Commit(ctx context.Context) error {
	if err := tx.Tx.Commit(ctx); err != nil {
		return err
	}
	return errInjectedCommitACKLoss
}

type rejectCommitBeforeDurabilityTx struct{ pgx.Tx }

func (tx *rejectCommitBeforeDurabilityTx) Commit(context.Context) error {
	// No commit is sent; deferred Rollback must release the PostgreSQL row.
	return errInjectedCommitACKLoss
}

func TestConsumeReconcilesRealCommittedTransactionWithLostACK(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	policy, signedReceipt, keys, assets := attemptFixture(t, store)
	store.beginConsume = func(ctx context.Context) (pgx.Tx, error) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		return &commitThenLoseACKTx{Tx: tx}, nil
	}
	_, err := store.ConsumeReviewEvidence(context.Background(), policy, signedReceipt, keys, assets)
	if !errors.Is(err, ErrAttemptCommitUnknown) || !errors.Is(err, errInjectedCommitACKLoss) {
		t.Fatalf("post-commit ACK loss not classified as uncertain: %v", err)
	}
	state, err := store.ReconcileReviewAttempt(context.Background(), policy, signedReceipt, keys, assets)
	if err != nil || state != AttemptConsumed {
		t.Fatalf("durably committed identical receipt not visible to reconciliation: state=%q err=%v", state, err)
	}
	store.beginConsume = nil
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, signedReceipt, keys, assets); !errors.Is(err, ErrAttemptUnavailable) {
		t.Fatalf("lost-ACK reconciliation granted a second review: %v", err)
	}
}

func TestConsumeReconcilesUncommittedACKLossAsPending(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	policy, signedReceipt, keys, assets := attemptFixture(t, store)
	store.beginConsume = func(ctx context.Context) (pgx.Tx, error) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		return &rejectCommitBeforeDurabilityTx{Tx: tx}, nil
	}
	_, err := store.ConsumeReviewEvidence(context.Background(), policy, signedReceipt, keys, assets)
	if !errors.Is(err, ErrAttemptCommitUnknown) {
		t.Fatalf("unacknowledged commit not classified as uncertain: %v", err)
	}
	state, err := store.ReconcileReviewAttempt(context.Background(), policy, signedReceipt, keys, assets)
	if err != nil || state != AttemptPending {
		t.Fatalf("uncommitted attempt mistaken for durable consumption: state=%q err=%v", state, err)
	}
	store.beginConsume = nil
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, signedReceipt, keys, assets); err != nil {
		t.Fatalf("explicit fresh consumption after authoritative pending check failed: %v", err)
	}
}
