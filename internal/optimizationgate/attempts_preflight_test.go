package optimizationgate

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// Invalid/replayed attempts must be rejected before opening external raw
// evidence. A signed but consumed receipt must not repeatedly fetch blobs.
type countingAttemptEvidenceReader struct {
	testEvidenceReader
	opens int
}

func (r *countingAttemptEvidenceReader) OpenEvidence(ctx context.Context, digest string) (io.ReadCloser, error) {
	r.opens++
	return r.testEvidenceReader.OpenEvidence(ctx, digest)
}

func TestAttemptConsumptionChecksNonceBeforeFetchingIndependentEvidence(t *testing.T) {
	store, _ := disposableAttemptStore(t)
	policy, wire, keys, assets := attemptFixture(t, store)
	ctx := context.Background()

	t.Run("authentic but never issued", func(t *testing.T) {
		unissued := policy
		unissued.VerificationNonce = strings.Repeat("e", 64)
		signedUnissued := signedVariant(t, wire, func(r *EvaluationReceipt) {
			r.VerificationNonce = unissued.VerificationNonce
		})
		reader := &countingAttemptEvidenceReader{testEvidenceReader: assets}
		_, err := store.ConsumeReviewEvidence(ctx, unissued, signedUnissued, keys, reader)
		if !errors.Is(err, ErrAttemptUnavailable) || reader.opens != 0 {
			t.Fatalf("unissued validly signed receipt caused blob fetch: opens=%d err=%v", reader.opens, err)
		}
	})

	if _, err := store.ConsumeReviewEvidence(ctx, policy, wire, keys, assets); err != nil {
		t.Fatalf("initial authentic receipt should consume normally: %v", err)
	}

	t.Run("authentic but already consumed", func(t *testing.T) {
		reader := &countingAttemptEvidenceReader{testEvidenceReader: assets}
		_, err := store.ConsumeReviewEvidence(ctx, policy, wire, keys, reader)
		if !errors.Is(err, ErrAttemptUnavailable) || reader.opens != 0 {
			t.Fatalf("consumed authentic receipt caused repeat blob fetch: opens=%d err=%v", reader.opens, err)
		}
	})
}
