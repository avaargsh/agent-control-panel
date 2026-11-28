package evidencepackage

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestSecurityEvaluationEvidenceIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*EvaluationPlan, *EvaluationReport, map[string][]byte)
		want EvaluationOutcome
	}{
		{"complete", func(*EvaluationPlan, *EvaluationReport, map[string][]byte) {}, EvaluationPass},
		{"missing-bytes", func(_ *EvaluationPlan, _ *EvaluationReport, e map[string][]byte) { delete(e, "network") }, EvaluationHold},
		{"empty-bytes", func(_ *EvaluationPlan, _ *EvaluationReport, e map[string][]byte) { e["network"] = nil }, EvaluationHold},
		{"changed-bytes", func(_ *EvaluationPlan, _ *EvaluationReport, e map[string][]byte) { e["network"] = []byte("changed") }, EvaluationHold},
		{"extra-bytes", func(_ *EvaluationPlan, _ *EvaluationReport, e map[string][]byte) { e["extra"] = []byte("extra") }, EvaluationHold},
		{"oversized-bytes", func(_ *EvaluationPlan, r *EvaluationReport, e map[string][]byte) {
			e["network"] = make([]byte, (64<<10)+1)
			r.Findings[1].EvidenceDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(e["network"]))
		}, EvaluationHold},
		{"valid-failure", func(_ *EvaluationPlan, r *EvaluationReport, _ map[string][]byte) {
			r.Findings[1].Outcome = EvaluationFail
		}, EvaluationFail},
		{"partial-failure", func(_ *EvaluationPlan, r *EvaluationReport, e map[string][]byte) {
			r.Findings = r.Findings[:1]
			r.Findings[0].Outcome = EvaluationFail
			delete(e, "network")
		}, EvaluationFail},
		{"partial-pass", func(_ *EvaluationPlan, r *EvaluationReport, e map[string][]byte) {
			r.Findings = r.Findings[:1]
			delete(e, "network")
		}, EvaluationHold},
		{"wrong-run", func(_ *EvaluationPlan, r *EvaluationReport, _ map[string][]byte) { r.Binding.RunID = "other" }, EvaluationHold},
		{"invalid-failure-evidence", func(_ *EvaluationPlan, r *EvaluationReport, e map[string][]byte) {
			r.Findings[1].Outcome = EvaluationFail
			e["network"] = []byte("changed")
		}, EvaluationHold},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding := EvaluationBinding{TenantID: "tenant-1", RunID: "run-1", PolicyDigest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("plan"))), VerifierRunID: "verifier-1"}
			p := EvaluationPlan{Binding: binding, Required: []string{"filesystem", "network"}}
			e := map[string][]byte{"filesystem": []byte("filesystem fixture"), "network": []byte("network fixture")}
			r := EvaluationReport{Binding: binding, Findings: []EvaluationFinding{
				{ScenarioID: "filesystem", Outcome: EvaluationPass, EvidenceDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(e["filesystem"]))},
				{ScenarioID: "network", Outcome: EvaluationPass, EvidenceDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(e["network"]))},
			}}
			tc.edit(&p, &r, e)
			if got := SummarizeEvaluationWithEvidence(p, r, e); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
