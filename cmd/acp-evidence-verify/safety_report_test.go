package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	ep "github.com/avaargsh/agent-control-panel/internal/evidencepackage"
)

func TestSafetyReportCLI(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	hash := func(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
	encode := func(v any) []byte {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	policy := encode(ep.SafetyEvaluationPolicy{Schema: ep.SafetyEvaluationPolicySchema, Version: "v1", Infrastructure: []string{"infra"}, Behavioral: []string{"behavior"}})
	fixture := func(id string, outcome ep.EvaluationOutcome) (ep.EvaluationDimensionTrust, ep.EvaluationDimensionReceipt) {
		key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		binding := ep.EvaluationBinding{TenantID: "tenant-1", RunID: "run-1", PolicyDigest: hash(policy), VerifierRunID: "verify-" + id}
		data := []byte("synthetic fixture")
		raw := encode(ep.EvaluationReport{Binding: binding, Findings: []ep.EvaluationFinding{{ScenarioID: id, Outcome: outcome, EvidenceDigest: hash(data)}}})
		return ep.EvaluationDimensionTrust{Plan: ep.EvaluationPlan{Binding: binding, Required: []string{id}}, Window: ep.EvaluationReceiptWindow{ReportDigest: hash(raw), NotBefore: now, ExpiresAt: now.Add(time.Hour)}, Key: key.Public().(ed25519.PublicKey)}, ep.EvaluationDimensionReceipt{Raw: raw, Signature: ed25519.Sign(key, append([]byte(ep.EvaluationReportSignatureDomain), raw...)), Evidence: map[string][]byte{id: data}}
	}
	for _, tc := range []struct {
		name    string
		outcome ep.EvaluationOutcome
		change  func(*safetyReportTrust, *safetyReportSubmission)
		want    ep.EvaluationOutcome
	}{
		{"pass", ep.EvaluationPass, nil, ep.EvaluationPass},
		{"fail", ep.EvaluationFail, nil, ep.EvaluationFail},
		{"hold", ep.EvaluationPass, func(_ *safetyReportTrust, s *safetyReportSubmission) { s.Behavioral.Raw = nil }, ep.EvaluationHold},
		{"expired", ep.EvaluationPass, func(a *safetyReportTrust, _ *safetyReportSubmission) { a.Behavioral.Window.ExpiresAt = now }, ep.EvaluationHold},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, ar := fixture("infra", ep.EvaluationPass)
			b, br := fixture("behavior", tc.outcome)
			trust := safetyReportTrust{Policy: policy, Infrastructure: a, Behavioral: b}
			submission := safetyReportSubmission{Infrastructure: ar, Behavioral: br}
			if tc.change != nil {
				tc.change(&trust, &submission)
			}
			dir := t.TempDir()
			tp, sp := filepath.Join(dir, "trust.json"), filepath.Join(dir, "submission.json")
			if err := os.WriteFile(tp, encode(trust), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sp, encode(submission), 0600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err := runSafetyReport([]string{"--trust", tp, "--submission", sp}, &out, now)
			if (err == nil) != (tc.want == ep.EvaluationPass) {
				t.Fatalf("unexpected error %v", err)
			}
			var summary ep.SafetyDimensionSummary
			if err := json.Unmarshal(out.Bytes(), &summary); err != nil || summary.Overall != tc.want {
				t.Fatalf("summary %+v, error %v", summary, err)
			}
		})
	}
}

func TestSafetyReportMissingInputs(t *testing.T) {
	var out bytes.Buffer
	if err := runSafetyReport(nil, &out, time.Now()); err == nil || out.Len() != 0 {
		t.Fatal("missing trust inputs must block")
	}
}
