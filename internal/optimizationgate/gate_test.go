package optimizationgate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func fixture() (BaselinePolicy, EvaluationReceipt, ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	p := BaselinePolicy{
		ExperimentID: "exp-1", TenantID: "tenant-a", ProjectID: "project-a",
		CandidateSHA:           strings.Repeat("a", 40),
		ExperimentBaselineSHA:  strings.Repeat("b", 40),
		IntegrationBaselineSHA: strings.Repeat("c", 40),
		EvaluationDigest:       "sha256:" + strings.Repeat("d", 64),
		WorkloadDigest:         "sha256:" + strings.Repeat("e", 64),
		EnvironmentDigest:      "sha256:" + strings.Repeat("f", 64),
		VerifierKeyID:          "independent-v1",
		ExpectedWorkItems:      100, MinimumQualityPasses: 100, MinimumOutputTokens: 2000,
	}
	r := EvaluationReceipt{
		Schema: ReceiptSchema, ExperimentID: p.ExperimentID, TenantID: p.TenantID, ProjectID: p.ProjectID,
		CandidateSHA: p.CandidateSHA, ExperimentBaselineSHA: p.ExperimentBaselineSHA,
		IntegrationBaselineSHA: p.IntegrationBaselineSHA, EvaluationDigest: p.EvaluationDigest,
		WorkloadDigest: p.WorkloadDigest, BaselineEnvironmentDigest: p.EnvironmentDigest,
		CandidateEnvironmentDigest: p.EnvironmentDigest, VerifierRunID: "independent-run-1",
		BaselineWorkItems: 100, CandidateWorkItems: 100,
		BaselineOutputTokens: 2050, CandidateOutputTokens: 2050,
		BaselineQualityPasses: 100, CandidateQualityPasses: 100,
		BaselineDurationNS: 10_000_000_000, CandidateDurationNS: 9_000_000_000,
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x7}, ed25519.SeedSize))
	return p, r, private, map[string]ed25519.PublicKey{"independent-v1": private.Public().(ed25519.PublicKey)}
}

func signed(r EvaluationReceipt, private ed25519.PrivateKey) []byte {
	payload, _ := json.Marshal(r)
	wire, _ := json.Marshal(SignedReceipt{
		KeyID: "independent-v1", Payload: payload,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload)),
	})
	return wire
}

func TestValidIndependentEvidenceIsEligibleForReviewOnly(t *testing.T) {
	policy, receipt, key, keys := fixture()
	got, err := VerifyReviewEvidence(policy, signed(receipt, key), keys)
	if err != nil {
		t.Fatal(err)
	}
	if got.VerifierRunID != "independent-run-1" || got.CandidateDurationNS >= got.BaselineDurationNS {
		t.Fatalf("incorrect independently verified receipt: %+v", got)
	}
}

func TestRejectsInvalidIndependentResults(t *testing.T) {
	cases := map[string]func(*EvaluationReceipt){
		"wrong tenant":                  func(r *EvaluationReceipt) { r.TenantID = "tenant-other" },
		"changed candidate sha":         func(r *EvaluationReceipt) { r.CandidateSHA = strings.Repeat("1", 40) },
		"changed experiment baseline":   func(r *EvaluationReceipt) { r.ExperimentBaselineSHA = strings.Repeat("2", 40) },
		"changed integration baseline":  func(r *EvaluationReceipt) { r.IntegrationBaselineSHA = strings.Repeat("3", 40) },
		"evaluation tampered":           func(r *EvaluationReceipt) { r.EvaluationDigest = "sha256:" + strings.Repeat("1", 64) },
		"workload tampered":             func(r *EvaluationReceipt) { r.WorkloadDigest = "sha256:" + strings.Repeat("1", 64) },
		"hardware changed":              func(r *EvaluationReceipt) { r.CandidateEnvironmentDigest = "sha256:" + strings.Repeat("1", 64) },
		"shortened candidate workload":  func(r *EvaluationReceipt) { r.CandidateWorkItems = 10 },
		"shortened baseline workload":   func(r *EvaluationReceipt) { r.BaselineWorkItems = 10 },
		"early eos output truncation":   func(r *EvaluationReceipt) { r.CandidateOutputTokens = 50 },
		"partial output above floor":    func(r *EvaluationReceipt) { r.CandidateOutputTokens = 2010 },
		"quality exceeds workload":      func(r *EvaluationReceipt) { r.CandidateQualityPasses = 101 },
		"baseline output too short":     func(r *EvaluationReceipt) { r.BaselineOutputTokens = 50 },
		"quality regressed":             func(r *EvaluationReceipt) { r.CandidateQualityPasses = 99 },
		"baseline quality below policy": func(r *EvaluationReceipt) { r.BaselineQualityPasses = 99 },
		"safety violation":              func(r *EvaluationReceipt) { r.SafetyViolations = 1 },
		"no verified speedup":           func(r *EvaluationReceipt) { r.CandidateDurationNS = r.BaselineDurationNS },
		"zero duration":                 func(r *EvaluationReceipt) { r.CandidateDurationNS = 0 },
		"missing verifier run":          func(r *EvaluationReceipt) { r.VerifierRunID = "" },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			policy, receipt, key, keys := fixture()
			alter(&receipt)
			if _, err := VerifyReviewEvidence(policy, signed(receipt, key), keys); !errors.Is(err, ErrEvaluationFailed) {
				t.Fatalf("unsafe result accepted or wrong error: %v", err)
			}
		})
	}
}

func TestRejectsUntrustedOrAmbiguousSignedEvidence(t *testing.T) {
	policy, receipt, key, keys := fixture()
	valid := signed(receipt, key)
	for name, wire := range map[string][]byte{
		"tampered payload":       bytes.Replace(valid, []byte(`"candidate_work_items":100`), []byte(`"candidate_work_items":10`), 1),
		"duplicate envelope key": bytes.Replace(valid, []byte(`"key_id":`), []byte(`"key_id":"independent-v1","key_id":`), 1),
		"unknown envelope field": bytes.Replace(valid, []byte(`"key_id":`), []byte(`"unexpected":true,"key_id":`), 1),
		"broken signature":       bytes.Replace(valid, []byte(`"signature":"`), []byte(`"signature":"bad`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyReviewEvidence(policy, wire, keys); err == nil {
				t.Fatal("ambiguous or unsigned evidence accepted")
			}
		})
	}
	if _, err := VerifyReviewEvidence(policy, valid, map[string]ed25519.PublicKey{}); !errors.Is(err, ErrUntrustedReceipt) {
		t.Fatalf("unknown key not rejected: %v", err)
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := VerifyReviewEvidence(policy, valid, map[string]ed25519.PublicKey{"independent-v1": wrong}); !errors.Is(err, ErrUntrustedReceipt) {
		t.Fatalf("wrong verifier key not rejected: %v", err)
	}
	payload, _ := json.Marshal(receipt)
	payload = bytes.Replace(payload, []byte(`"candidate_work_items":100`), []byte(`"candidate_work_items":100,"candidate_work_items":100`), 1)
	dupWire, _ := json.Marshal(SignedReceipt{KeyID: "independent-v1", Payload: payload, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))})
	if _, err := VerifyReviewEvidence(policy, dupWire, keys); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("even correctly signed duplicate-key payload must fail: %v", err)
	}
}

func TestRejectsCrossScopeVerifierKeyEvenWhenGloballyTrusted(t *testing.T) {
	policy, receipt, _, keys := fixture()
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x8}, ed25519.SeedSize))
	keys["other-scope"] = other.Public().(ed25519.PublicKey)
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(SignedReceipt{
		KeyID: "other-scope", Payload: payload,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(other, payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReviewEvidence(policy, wire, keys); !errors.Is(err, ErrUntrustedReceipt) {
		t.Fatalf("a globally trusted but unbound verifier must not approve this experiment: %v", err)
	}
}


func TestRejectsUnsafeVerifierRunIdentity(t *testing.T) {
	for _, runID := range []string{"../run", "other/run", "run\nspoof", "run\u200bhidden", strings.Repeat("r", 129)} {
		t.Run(strings.ReplaceAll(runID, "\n", "-newline-"), func(t *testing.T) {
			policy, receipt, key, keys := fixture()
			receipt.VerifierRunID = runID
			if _, err := VerifyReviewEvidence(policy, signed(receipt, key), keys); !errors.Is(err, ErrEvaluationFailed) {
				t.Fatalf("unsafe verifier Run ID should fail closed: %q err=%v", runID, err)
			}
		})
	}
}

func TestRejectsUnpinnedBaselinePolicy(t *testing.T) {
	p, r, k, keys := fixture()
	p.EvaluationDigest = "main"
	if _, err := VerifyReviewEvidence(p, signed(r, k), keys); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("untrusted rule digest: %v", err)
	}
	p, r, k, keys = fixture()
	p.ExpectedWorkItems = 0
	if _, err := VerifyReviewEvidence(p, signed(r, k), keys); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("unbounded work: %v", err)
	}
}
