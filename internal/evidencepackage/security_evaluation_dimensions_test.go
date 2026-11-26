package evidencepackage

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func dimensionFixture(t *testing.T, now time.Time, scenario, verifier string, outcome EvaluationOutcome) (EvaluationDimensionTrust, EvaluationDimensionReceipt) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	hash := func(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
	data := []byte("synthetic fixture: " + scenario)
	binding := EvaluationBinding{TenantID: "tenant-1", RunID: "run-1", PolicyDigest: hash([]byte("fixture policy")), VerifierRunID: verifier}
	plan := EvaluationPlan{Binding: binding, Required: []string{scenario}}
	raw, err := json.Marshal(EvaluationReport{Binding: binding, Findings: []EvaluationFinding{{ScenarioID: scenario, Outcome: outcome, EvidenceDigest: hash(data)}}})
	if err != nil {
		t.Fatal(err)
	}
	trust := EvaluationDimensionTrust{Plan: plan, Window: EvaluationReceiptWindow{ReportDigest: hash(raw), NotBefore: now, ExpiresAt: now.Add(time.Hour)}, Key: key.Public().(ed25519.PublicKey)}
	receipt := EvaluationDimensionReceipt{Raw: raw, Signature: ed25519.Sign(key, append([]byte(EvaluationReportSignatureDomain), raw...)), Evidence: map[string][]byte{scenario: data}}
	return trust, receipt
}

func TestSafetyDimensions(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name            string
		infra, behavior EvaluationOutcome
		edit            func(*EvaluationDimensionTrust, *EvaluationDimensionTrust, *EvaluationDimensionReceipt, *EvaluationDimensionReceipt)
		want            SafetyDimensionSummary
	}{
		{"both-pass", EvaluationPass, EvaluationPass, nil, SafetyDimensionSummary{EvaluationPass, EvaluationPass, EvaluationPass}},
		{"infrastructure-fails", EvaluationFail, EvaluationPass, nil, SafetyDimensionSummary{EvaluationFail, EvaluationPass, EvaluationFail}},
		{"behavior-fails", EvaluationPass, EvaluationFail, nil, SafetyDimensionSummary{EvaluationPass, EvaluationFail, EvaluationFail}},
		{"missing-behavior", EvaluationPass, EvaluationPass, func(_, _ *EvaluationDimensionTrust, _, b *EvaluationDimensionReceipt) { b.Raw = nil }, SafetyDimensionSummary{EvaluationPass, EvaluationHold, EvaluationHold}},
		{"failure-and-missing", EvaluationFail, EvaluationPass, func(_, _ *EvaluationDimensionTrust, _, b *EvaluationDimensionReceipt) { b.Raw = nil }, SafetyDimensionSummary{EvaluationFail, EvaluationHold, EvaluationFail}},
		{"missing-infrastructure", EvaluationPass, EvaluationPass, func(_, _ *EvaluationDimensionTrust, a, _ *EvaluationDimensionReceipt) { a.Evidence = nil }, SafetyDimensionSummary{EvaluationHold, EvaluationPass, EvaluationHold}},
		{"different-run", EvaluationPass, EvaluationPass, func(_, b *EvaluationDimensionTrust, _, _ *EvaluationDimensionReceipt) { b.Plan.Binding.RunID = "other" }, SafetyDimensionSummary{EvaluationHold, EvaluationHold, EvaluationHold}},
		{"different-tenant", EvaluationPass, EvaluationPass, func(_, b *EvaluationDimensionTrust, _, _ *EvaluationDimensionReceipt) {
			b.Plan.Binding.TenantID = "other"
		}, SafetyDimensionSummary{EvaluationHold, EvaluationHold, EvaluationHold}},
		{"different-policy", EvaluationPass, EvaluationPass, func(_, b *EvaluationDimensionTrust, _, _ *EvaluationDimensionReceipt) {
			b.Plan.Binding.PolicyDigest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("other policy")))
		}, SafetyDimensionSummary{EvaluationHold, EvaluationHold, EvaluationHold}},
		{"swapped-receipts", EvaluationPass, EvaluationPass, func(_, _ *EvaluationDimensionTrust, a, b *EvaluationDimensionReceipt) { *a, *b = *b, *a }, SafetyDimensionSummary{EvaluationHold, EvaluationHold, EvaluationHold}},
		{"same-verifier-run", EvaluationPass, EvaluationPass, func(a, b *EvaluationDimensionTrust, _, _ *EvaluationDimensionReceipt) {
			b.Plan.Binding.VerifierRunID = a.Plan.Binding.VerifierRunID
		}, SafetyDimensionSummary{EvaluationHold, EvaluationHold, EvaluationHold}},
		{"overlapping-scenarios", EvaluationPass, EvaluationPass, func(a, b *EvaluationDimensionTrust, _, _ *EvaluationDimensionReceipt) {
			b.Plan.Required = append(b.Plan.Required, a.Plan.Required[0])
		}, SafetyDimensionSummary{EvaluationHold, EvaluationHold, EvaluationHold}},
		{"empty-dimension-plan", EvaluationPass, EvaluationPass, func(_, b *EvaluationDimensionTrust, _, _ *EvaluationDimensionReceipt) { b.Plan.Required = nil }, SafetyDimensionSummary{EvaluationHold, EvaluationHold, EvaluationHold}},
		{"expired-behavior", EvaluationPass, EvaluationPass, func(_, b *EvaluationDimensionTrust, _, _ *EvaluationDimensionReceipt) { b.Window.ExpiresAt = now }, SafetyDimensionSummary{EvaluationPass, EvaluationHold, EvaluationHold}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, ar := dimensionFixture(t, now, "infrastructure-fixture", "verifier-infra", tc.infra)
			b, br := dimensionFixture(t, now, "behavior-fixture", "verifier-behavior", tc.behavior)
			if tc.edit != nil {
				tc.edit(&a, &b, &ar, &br)
			}
			if got := EvaluateSafetyDimensions(a, ar, b, br, now); got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}
