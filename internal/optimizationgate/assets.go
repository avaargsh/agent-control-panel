package optimizationgate

import (
	"context"
	"crypto/ed25519"
	"errors"
)

const maxEvidenceBytes = 32 << 20

var ErrEvidenceInvalid = errors.New("independent raw evaluation evidence is missing or invalid")

// EvidenceReader must be supplied by trusted ACP configuration and must
// retrieve immutable byte-addressed objects. Candidate-controlled readers are
// not an authority.
type EvidenceReader interface {
	ReadEvidence(context.Context, string) ([]byte, error)
}

// VerifyReviewEvidenceWithAssets is intentionally incomplete on this
// test-only commit: it demonstrates that signature-only verification does not
// re-read or authenticate referenced raw evidence.
func VerifyReviewEvidenceWithAssets(
	ctx context.Context, policy BaselinePolicy, signedReceipt []byte,
	keys map[string]ed25519.PublicKey, reader EvidenceReader,
) (EvaluationReceipt, error) {
	return VerifyReviewEvidence(policy, signedReceipt, keys)
}
