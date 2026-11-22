// Package optimizationgate checks independently signed experiment results for
// review eligibility. It does not execute benchmarks, authorize GPU usage,
// create PRs, approve protected effects, or promote production releases.
package optimizationgate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const ReceiptSchema = "acp.optimization.verification/v1"
const maxSignedReceiptBytes = 64 * 1024

var (
	ErrInvalidContract  = errors.New("invalid optimization evidence contract")
	ErrUntrustedReceipt = errors.New("untrusted independent verifier receipt")
	ErrEvaluationFailed = errors.New("optimization verification criteria not met")
)

// BaselinePolicy must be supplied from a trusted, immutable experiment/rules
// authority. Never construct it from a candidate-owned proposal or receipt.
type BaselinePolicy struct {
	ExperimentID           string
	TenantID               string
	ProjectID              string
	CandidateSHA           string
	ExperimentBaselineSHA  string
	IntegrationBaselineSHA string
	EvaluationDigest       string
	WorkloadDigest         string
	EnvironmentDigest      string
	ExpectedWorkItems      int64
	MinimumQualityPasses   int64
	MinimumOutputTokens    int64 // 0 for non-token workloads
}

// EvaluationReceipt is a result from an isolated independent verifier. The
// pinned workload must define what a work item, quality pass and token mean.
// It must not be signed by the candidate Agent or its experiment executor.
type EvaluationReceipt struct {
	Schema                     string `json:"schema"`
	ExperimentID               string `json:"experiment_id"`
	TenantID                   string `json:"tenant_id"`
	ProjectID                  string `json:"project_id"`
	CandidateSHA               string `json:"candidate_sha"`
	ExperimentBaselineSHA      string `json:"experiment_baseline_sha"`
	IntegrationBaselineSHA     string `json:"integration_baseline_sha"`
	EvaluationDigest           string `json:"evaluation_digest"`
	WorkloadDigest             string `json:"workload_digest"`
	BaselineEnvironmentDigest  string `json:"baseline_environment_digest"`
	CandidateEnvironmentDigest string `json:"candidate_environment_digest"`
	VerifierRunID              string `json:"verifier_run_id"`
	BaselineWorkItems          int64  `json:"baseline_work_items"`
	CandidateWorkItems         int64  `json:"candidate_work_items"`
	BaselineOutputTokens       int64  `json:"baseline_output_tokens"`
	CandidateOutputTokens      int64  `json:"candidate_output_tokens"`
	BaselineQualityPasses      int64  `json:"baseline_quality_passes"`
	CandidateQualityPasses     int64  `json:"candidate_quality_passes"`
	SafetyViolations           int64  `json:"safety_violations"`
	BaselineDurationNS         int64  `json:"baseline_duration_ns"`
	CandidateDurationNS        int64  `json:"candidate_duration_ns"`
}

type SignedReceipt struct {
	KeyID     string          `json:"key_id"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

// VerifyReviewEvidence checks a pinned policy and an Ed25519-signed,
// canonical JSON receipt. The returned receipt is eligible for HUMAN REVIEW
// only; Guard approval, actual GPU release/cost authority and PR promotion
// are separate independent gates. The supplied verifierKeys must be trusted
// configuration, not an Agent-controlled value.
func VerifyReviewEvidence(policy BaselinePolicy, wire []byte, verifierKeys map[string]ed25519.PublicKey) (EvaluationReceipt, error) {
	if !validPolicy(policy) {
		return EvaluationReceipt{}, ErrInvalidContract
	}
	if len(wire) == 0 || len(wire) > maxSignedReceiptBytes {
		return EvaluationReceipt{}, ErrInvalidContract
	}

	var envelope SignedReceipt
	if err := decodeCanonical(wire, &envelope); err != nil {
		return EvaluationReceipt{}, err
	}
	publicKey, ok := verifierKeys[envelope.KeyID]
	if !ok || len(publicKey) != ed25519.PublicKeySize || envelope.KeyID == "" {
		return EvaluationReceipt{}, ErrUntrustedReceipt
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, envelope.Payload, signature) {
		return EvaluationReceipt{}, ErrUntrustedReceipt
	}

	var receipt EvaluationReceipt
	if err := decodeCanonical(envelope.Payload, &receipt); err != nil {
		return EvaluationReceipt{}, err
	}
	if receipt.Schema != ReceiptSchema ||
		receipt.ExperimentID != policy.ExperimentID || receipt.TenantID != policy.TenantID || receipt.ProjectID != policy.ProjectID ||
		receipt.CandidateSHA != policy.CandidateSHA || receipt.ExperimentBaselineSHA != policy.ExperimentBaselineSHA ||
		receipt.IntegrationBaselineSHA != policy.IntegrationBaselineSHA || receipt.EvaluationDigest != policy.EvaluationDigest ||
		receipt.WorkloadDigest != policy.WorkloadDigest || receipt.BaselineEnvironmentDigest != policy.EnvironmentDigest ||
		receipt.CandidateEnvironmentDigest != policy.EnvironmentDigest || receipt.VerifierRunID == "" ||
		strings.TrimSpace(receipt.VerifierRunID) != receipt.VerifierRunID ||
		receipt.BaselineWorkItems != policy.ExpectedWorkItems || receipt.CandidateWorkItems != policy.ExpectedWorkItems ||
		receipt.BaselineOutputTokens < policy.MinimumOutputTokens || receipt.CandidateOutputTokens < policy.MinimumOutputTokens ||
		(policy.MinimumOutputTokens > 0 && receipt.CandidateOutputTokens < receipt.BaselineOutputTokens) ||
		receipt.BaselineQualityPasses < policy.MinimumQualityPasses ||
		receipt.BaselineQualityPasses > receipt.BaselineWorkItems ||
		receipt.CandidateQualityPasses > receipt.CandidateWorkItems ||
		receipt.CandidateQualityPasses < policy.MinimumQualityPasses ||
		receipt.CandidateQualityPasses < receipt.BaselineQualityPasses ||
		receipt.SafetyViolations != 0 || receipt.BaselineDurationNS <= 0 ||
		receipt.CandidateDurationNS <= 0 || receipt.CandidateDurationNS >= receipt.BaselineDurationNS {
		return EvaluationReceipt{}, ErrEvaluationFailed
	}
	return receipt, nil
}

// decodeCanonical disallows alternate spellings, duplicate/unknown fields,
// trailing bytes and non-canonical encodings even when a receipt is signed.
func decodeCanonical(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidContract, err)
	}
	canonical, err := json.Marshal(dst)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrInvalidContract
	}
	return nil
}

func validPolicy(p BaselinePolicy) bool {
	if p.ExperimentID == "" || p.TenantID == "" || p.ProjectID == "" ||
		strings.TrimSpace(p.ExperimentID) != p.ExperimentID ||
		strings.TrimSpace(p.TenantID) != p.TenantID || strings.TrimSpace(p.ProjectID) != p.ProjectID ||
		!hexString(p.CandidateSHA, 40) || !hexString(p.ExperimentBaselineSHA, 40) ||
		!hexString(p.IntegrationBaselineSHA, 40) || !digest(p.EvaluationDigest) ||
		!digest(p.WorkloadDigest) || !digest(p.EnvironmentDigest) ||
		p.ExpectedWorkItems <= 0 || p.MinimumQualityPasses <= 0 ||
		p.MinimumQualityPasses > p.ExpectedWorkItems || p.MinimumOutputTokens < 0 {
		return false
	}
	return true
}
func digest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && hexString(strings.TrimPrefix(s, "sha256:"), 64)
}
func hexString(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
		return false
	}
	}
	return true
}
