package optimizationgate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
)

const maxEvidenceBytes = 32 << 20

var ErrEvidenceInvalid = errors.New("independent raw evaluation evidence is missing or invalid")

// EvidenceReader is a trusted, host-injected capability to load immutable,
// content-addressed evaluation artifacts. Agent-supplied readers and
// candidate-controlled object stores are NOT independent proof.
type EvidenceReader interface {
	ReadEvidence(context.Context, string) ([]byte, error)
}

// VerifyReviewEvidenceWithAssets extends the offline signed-claim check by
// independently reloading both raw evidence objects and recomputing SHA-256.
// It returns review eligibility ONLY, never permission to promote or execute.
// This library cannot prove the reader's independent IAM, immutability,
// retention or the correctness of the verifier's measurements.
func VerifyReviewEvidenceWithAssets(
	ctx context.Context, policy BaselinePolicy, signedReceipt []byte,
	keys map[string]ed25519.PublicKey, reader EvidenceReader,
) (EvaluationReceipt, error) {
	if ctx == nil {
		return EvaluationReceipt{}, ErrEvidenceInvalid
	}
	if err := ctx.Err(); err != nil {
		return EvaluationReceipt{}, err
	}
	receipt, err := VerifyReviewEvidence(policy, signedReceipt, keys)
	if err != nil {
		return EvaluationReceipt{}, err
	}
	if !evidenceReaderConfigured(reader) {
		return EvaluationReceipt{}, ErrEvidenceInvalid
	}
	for _, claimed := range []string{receipt.BaselineEvidenceDigest, receipt.CandidateEvidenceDigest} {
		if err := ctx.Err(); err != nil {
			return EvaluationReceipt{}, err
		}
		raw, err := reader.ReadEvidence(ctx, claimed)
		if err != nil {
			return EvaluationReceipt{}, fmt.Errorf("%w: evidence fetch failed: %v", ErrEvidenceInvalid, err)
		}
		if len(raw) == 0 || len(raw) > maxEvidenceBytes {
			return EvaluationReceipt{}, ErrEvidenceInvalid
		}
		hash := sha256.Sum256(raw)
		if claimed != "sha256:"+hex.EncodeToString(hash[:]) {
			return EvaluationReceipt{}, ErrEvidenceInvalid
		}
	}
	return receipt, nil
}

func evidenceReaderConfigured(reader EvidenceReader) bool {
	if reader == nil {
		return false
	}
	v := reflect.ValueOf(reader)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}
