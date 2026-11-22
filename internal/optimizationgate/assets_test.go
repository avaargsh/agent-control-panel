package optimizationgate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"
)

type testEvidenceReader map[string][]byte

func (r testEvidenceReader) ReadEvidence(_ context.Context, digest string) ([]byte, error) {
	data, ok := r[digest]
	if !ok {
		return nil, fmt.Errorf("missing evidence %s", digest)
	}
	return data, nil
}

func evidenceSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func evidenceFixture(t *testing.T) (BaselinePolicy, []byte, map[string]ed25519.PublicKey, testEvidenceReader) {
	t.Helper()
	policy, receipt, key, keys := fixture()
	baseline := []byte(`{"case":"frozen","output":100}`)
	candidate := []byte(`{"case":"frozen","output":100,"improved":true}`)
	receipt.BaselineEvidenceDigest = evidenceSHA(baseline)
	receipt.CandidateEvidenceDigest = evidenceSHA(candidate)
	assets := testEvidenceReader{receipt.BaselineEvidenceDigest: baseline, receipt.CandidateEvidenceDigest: candidate}
	return policy, signed(receipt, key), keys, assets
}

func TestIndependentRawEvidenceMustMatchSignedDigests(t *testing.T) {
	policy, wire, keys, assets := evidenceFixture(t)
	got, err := VerifyReviewEvidenceWithAssets(context.Background(), policy, wire, keys, assets)
	if err != nil || got.VerifierRunID != "independent-run-1" {
		t.Fatalf("matching content-addressed raw evidence rejected: receipt=%+v err=%v", got, err)
	}
	tampered := testEvidenceReader{}
	for k, v := range assets {
		tampered[k] = bytes.Clone(v)
	}
	for k := range tampered {
		tampered[k][0] ^= 1
		break
	}
	if _, err := VerifyReviewEvidenceWithAssets(context.Background(), policy, wire, keys, tampered); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("mutable blob substitution must fail closed: %v", err)
	}
}

func TestIndependentRawEvidenceMissingOrOversizedFailsClosed(t *testing.T) {
	policy, wire, keys, assets := evidenceFixture(t)
	if _, err := VerifyReviewEvidenceWithAssets(context.Background(), policy, wire, keys, nil); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("nil trusted reader accepted: %v", err)
	}
	if _, err := VerifyReviewEvidenceWithAssets(context.Background(), policy, wire, keys, testEvidenceReader{}); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("missing immutable blob accepted: %v", err)
	}
	missing := testEvidenceReader{}
	for k, v := range assets {
		missing[k] = bytes.Clone(v)
	}
	for k := range missing {
		missing[k] = bytes.Repeat([]byte("x"), maxEvidenceBytes+1)
		break
	}
	if _, err := VerifyReviewEvidenceWithAssets(context.Background(), policy, wire, keys, missing); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("oversized evidence accepted: %v", err)
	}
}

func TestIndependentEvidenceRejectsCanceledContext(t *testing.T) {
	policy, wire, keys, assets := evidenceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyReviewEvidenceWithAssets(ctx, policy, wire, keys, assets); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled fetch should fail before review: %v", err)
	}
}

// streamingEvidenceProbe makes the old eager []byte retrieval fail on
// purpose, while serving valid, independently digest-pinned evidence through
// a bounded stream. The verifier must use the streaming route, not silently
// download an unbounded object before enforcing maxEvidenceBytes.
type streamingEvidenceProbe struct {
	testEvidenceReader
	opens int
}

func (r *streamingEvidenceProbe) ReadEvidence(context.Context, string) ([]byte, error) {
	return nil, errors.New("unbounded eager evidence fetch is forbidden")
}

func (r *streamingEvidenceProbe) OpenEvidence(ctx context.Context, digest string) (io.ReadCloser, error) {
	data, err := r.testEvidenceReader.ReadEvidence(ctx, digest)
	if err != nil {
		return nil, err
	}
	r.opens++
	return io.NopCloser(bytes.NewReader(data)), nil
}

func TestIndependentEvidencePrefersBoundedStreamingOverEagerByteFetch(t *testing.T) {
	policy, wire, keys, assets := evidenceFixture(t)
	reader := &streamingEvidenceProbe{testEvidenceReader: assets}
	receipt, err := VerifyReviewEvidenceWithAssets(context.Background(), policy, wire, keys, reader)
	if err != nil || receipt.VerifierRunID != "independent-run-1" || reader.opens != 2 {
		t.Fatalf("streaming evidence was not verified without eager fetch: receipt=%+v opens=%d err=%v", receipt, reader.opens, err)
	}
}
