package evidencepackage

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestPinnedSafetyPolicy(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	hash := func(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
	for _, tc := range []struct {
		name       string
		policyEdit func(*SafetyEvaluationPolicy)
		rawEdit    func([]byte) []byte
		pinEdited  bool
		want       EvaluationOutcome
	}{
		{name: "complete", want: EvaluationPass},
		{name: "missing-policy", rawEdit: func([]byte) []byte { return nil }, want: EvaluationHold},
		{name: "changed-policy", rawEdit: func([]byte) []byte { return []byte("{}") }, want: EvaluationHold},
		{name: "omitted-required-scenario", policyEdit: func(p *SafetyEvaluationPolicy) { p.Infrastructure = append(p.Infrastructure, "required") }, want: EvaluationHold},
		{name: "swapped-dimensions", policyEdit: func(p *SafetyEvaluationPolicy) { p.Infrastructure, p.Behavioral = p.Behavioral, p.Infrastructure }, want: EvaluationHold},
		{name: "wrong-schema", policyEdit: func(p *SafetyEvaluationPolicy) { p.Schema = "other" }, want: EvaluationHold},
		{name: "missing-version", policyEdit: func(p *SafetyEvaluationPolicy) { p.Version = "" }, want: EvaluationHold},
		{name: "noncanonical-policy", rawEdit: func(raw []byte) []byte { return append([]byte(" "), raw...) }, pinEdited: true, want: EvaluationHold},
		{name: "duplicate-scenario", policyEdit: func(p *SafetyEvaluationPolicy) { p.Infrastructure = []string{"infra", "infra"} }, want: EvaluationHold},
		{name: "empty-dimension", policyEdit: func(p *SafetyEvaluationPolicy) { p.Behavioral = nil }, want: EvaluationHold},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := SafetyEvaluationPolicy{Schema: SafetyEvaluationPolicySchema, Version: "v1", Infrastructure: []string{"infra"}, Behavioral: []string{"behavior"}}
			if tc.policyEdit != nil {
				tc.policyEdit(&p)
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			pin := hash(raw)
			if tc.rawEdit != nil {
				raw = tc.rawEdit(raw)
			}
			if tc.pinEdited {
				pin = hash(raw)
			}
			a, ar := dimensionFixture(t, now, "infra", "verify-infra", EvaluationPass)
			b, br := dimensionFixture(t, now, "behavior", "verify-behavior", EvaluationPass)
			for _, pair := range []struct {
				trust   *EvaluationDimensionTrust
				receipt *EvaluationDimensionReceipt
			}{{&a, &ar}, {&b, &br}} {
				pair.trust.Plan.Binding.PolicyDigest = pin
				var report EvaluationReport
				if err := json.Unmarshal(pair.receipt.Raw, &report); err != nil {
					t.Fatal(err)
				}
				report.Binding = pair.trust.Plan.Binding
				pair.receipt.Raw, err = json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
				pair.receipt.Signature = ed25519.Sign(key, append([]byte(EvaluationReportSignatureDomain), pair.receipt.Raw...))
				pair.trust.Window.ReportDigest = hash(pair.receipt.Raw)
			}
			if got := EvaluateSafetyDimensions(a, ar, b, br, now); got.Overall != EvaluationPass {
				t.Fatalf("fixture must independently verify: %+v", got)
			}
			if got := EvaluatePinnedSafetyPolicy(raw, a, ar, b, br, now); got != (SafetyDimensionSummary{tc.want, tc.want, tc.want}) {
				t.Fatalf("got %+v want %q", got, tc.want)
			}
		})
	}
}
