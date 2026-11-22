package optimizationgate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
)

const maxEvidenceBytes = 32 << 20

var ErrEvidenceInvalid = errors.New("independent raw evaluation evidence is missing or invalid")

// EvidenceReader is a trusted, host-injected *streaming* capability for
// immutable, content-addressed evaluation artifacts. An implementation MUST
// avoid eagerly buffering a remote object in OpenEvidence and MUST respect
// context cancellation. Agent-supplied readers/candidate-owned stores are NOT
// independent proof. The verifier bounds bytes consumed from the returned
// stream; independent IAM and object-retention are separate host obligations.
type EvidenceReader interface {
	OpenEvidence(context.Context, string) (io.ReadCloser, error)
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
		stream, err := reader.OpenEvidence(ctx, claimed)
		if err != nil {
			if evidenceReaderConfigured(stream) {
				_ = stream.Close()
			}
			return EvaluationReceipt{}, fmt.Errorf("%w: evidence open failed: %v", ErrEvidenceInvalid, err)
		}
		if !evidenceReaderConfigured(stream) {
			return EvaluationReceipt{}, ErrEvidenceInvalid
		}
		hash := sha256.New()
		// CopyN internally limits the source to maxEvidenceBytes+1. We
		// never materialize an unbounded object in the verifier process.
		// The extra byte distinguishes an exactly-full valid artifact
		// from an oversized stream, even if the remote reader never EOFs.
		size, readErr := io.CopyN(hash, stream, int64(maxEvidenceBytes)+1)
		closeErr := stream.Close()
		if err := ctx.Err(); err != nil {
			return EvaluationReceipt{}, err
		}
		if size == 0 || size > int64(maxEvidenceBytes) ||
			(readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil {
			return EvaluationReceipt{}, ErrEvidenceInvalid
		}
		if claimed != "sha256:"+hex.EncodeToString(hash.Sum(nil)) {
			return EvaluationReceipt{}, ErrEvidenceInvalid
		}
	}
	return receipt, nil
}

func evidenceReaderConfigured(reader any) bool {
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
