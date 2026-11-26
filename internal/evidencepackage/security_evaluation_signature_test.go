package evidencepackage

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
)

func TestSignedEvaluationReport(t *testing.T) {
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := EvaluationBinding{TenantID: "tenant-1", RunID: "run-1", PolicyDigest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("fixture-plan"))), VerifierRunID: "verifier-1"}
	plan := EvaluationPlan{Binding: binding, Required: []string{"filesystem"}}
	evidence := []byte("fixture evidence")
	report := EvaluationReport{Binding: binding, Findings: []EvaluationFinding{{ScenarioID: "filesystem", Outcome: EvaluationPass, EvidenceDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(evidence))}}}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	// Test-only key and signature. Production signing is outside ACP.
	sign := func(data []byte) []byte {
		return ed25519.Sign(private, append([]byte("acp.security-evaluation-report/v1\x00"), data...))
	}
	failure := report
	failure.Findings = append([]EvaluationFinding(nil), report.Findings...)
	failure.Findings[0].Outcome = EvaluationFail
	failedRaw, err := json.Marshal(failure)
	if err != nil {
		t.Fatal(err)
	}
	wrongRun := plan
	wrongRun.Binding.VerifierRunID = "verifier-2"
	for _, tc := range []struct {
		name string
		plan EvaluationPlan
		raw  []byte
		sig  []byte
		key  ed25519.PublicKey
		data []byte
		want EvaluationOutcome
	}{
		{"trusted-complete", plan, raw, sign(raw), key, evidence, EvaluationPass},
		{"trusted-failure", plan, failedRaw, sign(failedRaw), key, evidence, EvaluationFail},
		{"wrong-key", plan, raw, sign(raw), otherKey, evidence, EvaluationHold},
		{"missing-key", plan, raw, sign(raw), nil, evidence, EvaluationHold},
		{"missing-signature", plan, raw, nil, key, evidence, EvaluationHold},
		{"wrong-domain", plan, raw, ed25519.Sign(private, raw), key, evidence, EvaluationHold},
		{"wrong-verifier-run", wrongRun, raw, sign(raw), key, evidence, EvaluationHold},
		{"noncanonical-json", plan, append([]byte(" "), raw...), sign(append([]byte(" "), raw...)), key, evidence, EvaluationHold},
		{"missing-evidence", plan, raw, sign(raw), key, nil, EvaluationHold},
		{"changed-evidence", plan, raw, sign(raw), key, []byte("different fixture"), EvaluationHold},
		{"changed-report", plan, failedRaw, sign(raw), key, evidence, EvaluationHold},
		{"oversized-report", plan, make([]byte, (2<<20)+1), nil, key, evidence, EvaluationHold},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := VerifySignedEvaluationReport(tc.plan, tc.raw, tc.sig, tc.key, map[string][]byte{"filesystem": tc.data}); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
