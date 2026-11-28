package evidencepackage

import "testing"

func TestSecurityEvaluationResultContract(t *testing.T) {
	binding := EvaluationBinding{TenantID: "tenant-1", RunID: "run-1", PolicyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", VerifierRunID: "verify-1"}
	plan := EvaluationPlan{Binding: binding, Required: []string{"filesystem", "network"}}
	first := EvaluationFinding{ScenarioID: "filesystem", Outcome: EvaluationPass, EvidenceDigest: binding.PolicyDigest}
	second := EvaluationFinding{ScenarioID: "network", Outcome: EvaluationPass, EvidenceDigest: binding.PolicyDigest}
	for _, tc := range []struct {
		name string
		edit func(*EvaluationPlan, *EvaluationReport)
		want EvaluationOutcome
	}{
		{"complete", func(*EvaluationPlan, *EvaluationReport) {}, EvaluationPass},
		{"missing", func(_ *EvaluationPlan, r *EvaluationReport) { r.Findings = r.Findings[:1] }, EvaluationHold},
		{"failed", func(_ *EvaluationPlan, r *EvaluationReport) { r.Findings[1].Outcome = EvaluationFail }, EvaluationFail},
		{"failed-with-missing", func(_ *EvaluationPlan, r *EvaluationReport) {
			r.Findings = r.Findings[:1]
			r.Findings[0].Outcome = EvaluationFail
		}, EvaluationFail},
		{"incomplete", func(_ *EvaluationPlan, r *EvaluationReport) { r.Findings[1].Outcome = EvaluationHold }, EvaluationHold},
		{"no-evidence", func(_ *EvaluationPlan, r *EvaluationReport) { r.Findings[1].EvidenceDigest = "" }, EvaluationHold},
		{"wrong-run", func(_ *EvaluationPlan, r *EvaluationReport) { r.Binding.RunID = "other" }, EvaluationHold},
		{"wrong-policy", func(_ *EvaluationPlan, r *EvaluationReport) { r.Binding.PolicyDigest = "" }, EvaluationHold},
		{"wrong-verifier", func(_ *EvaluationPlan, r *EvaluationReport) { r.Binding.VerifierRunID = "other" }, EvaluationHold},
		{"wrong-tenant", func(_ *EvaluationPlan, r *EvaluationReport) { r.Binding.TenantID = "other" }, EvaluationHold},
		{"duplicate", func(_ *EvaluationPlan, r *EvaluationReport) { r.Findings[1] = r.Findings[0] }, EvaluationHold},
		{"unknown", func(_ *EvaluationPlan, r *EvaluationReport) { r.Findings[1].ScenarioID = "other" }, EvaluationHold},
		{"unknown-outcome", func(_ *EvaluationPlan, r *EvaluationReport) { r.Findings[1].Outcome = "SKIP" }, EvaluationHold},
		{"empty-plan", func(p *EvaluationPlan, _ *EvaluationReport) { p.Required = nil }, EvaluationHold},
		{"duplicate-plan", func(p *EvaluationPlan, _ *EvaluationReport) { p.Required = []string{"filesystem", "filesystem"} }, EvaluationHold},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := plan
			r := EvaluationReport{Binding: binding, Findings: []EvaluationFinding{first, second}}
			tc.edit(&p, &r)
			if got := SummarizeEvaluation(p, r); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
