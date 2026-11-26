package evidencepackage

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestPinnedEvaluationWindow(t *testing.T) {
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	data := []byte("fixture")
	digest := func(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
	binding := EvaluationBinding{TenantID: "tenant-1", RunID: "run-1", PolicyDigest: digest([]byte("plan")), VerifierRunID: "verifier-1"}
	plan := EvaluationPlan{Binding: binding, Required: []string{"filesystem"}}
	report := EvaluationReport{Binding: binding, Findings: []EvaluationFinding{{ScenarioID: "filesystem", Outcome: EvaluationPass, EvidenceDigest: digest(data)}}}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(private, append([]byte(EvaluationReportSignatureDomain), raw...))
	window := EvaluationReceiptWindow{ReportDigest: digest(raw), NotBefore: now, ExpiresAt: now.Add(time.Hour)}
	for _, tc := range []struct {
		name string
		edit func(*EvaluationReceiptWindow, *EvaluationPlan, *time.Time)
		want EvaluationOutcome
	}{
		{"start-inclusive", func(*EvaluationReceiptWindow, *EvaluationPlan, *time.Time) {}, EvaluationPass},
		{"within-window", func(_ *EvaluationReceiptWindow, _ *EvaluationPlan, n *time.Time) { *n = n.Add(time.Minute) }, EvaluationPass},
		{"before-window", func(_ *EvaluationReceiptWindow, _ *EvaluationPlan, n *time.Time) { *n = n.Add(-time.Nanosecond) }, EvaluationHold},
		{"expiry-exclusive", func(w *EvaluationReceiptWindow, _ *EvaluationPlan, n *time.Time) { *n = w.ExpiresAt }, EvaluationHold},
		{"expired", func(_ *EvaluationReceiptWindow, _ *EvaluationPlan, n *time.Time) { *n = n.Add(2 * time.Hour) }, EvaluationHold},
		{"missing-pin", func(w *EvaluationReceiptWindow, _ *EvaluationPlan, _ *time.Time) { w.ReportDigest = "" }, EvaluationHold},
		{"different-pin", func(w *EvaluationReceiptWindow, _ *EvaluationPlan, _ *time.Time) {
			w.ReportDigest = digest([]byte("different"))
		}, EvaluationHold},
		{"missing-start", func(w *EvaluationReceiptWindow, _ *EvaluationPlan, _ *time.Time) { w.NotBefore = time.Time{} }, EvaluationHold},
		{"missing-expiry", func(w *EvaluationReceiptWindow, _ *EvaluationPlan, _ *time.Time) { w.ExpiresAt = time.Time{} }, EvaluationHold},
		{"empty-window", func(w *EvaluationReceiptWindow, _ *EvaluationPlan, _ *time.Time) { w.ExpiresAt = w.NotBefore }, EvaluationHold},
		{"missing-clock", func(_ *EvaluationReceiptWindow, _ *EvaluationPlan, n *time.Time) { *n = time.Time{} }, EvaluationHold},
		{"different-verifier-run", func(_ *EvaluationReceiptWindow, p *EvaluationPlan, _ *time.Time) {
			p.Binding.VerifierRunID = "verifier-2"
		}, EvaluationHold},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, p, n := window, plan, now
			tc.edit(&w, &p, &n)
			if got := VerifyPinnedEvaluationReport(p, w, n, raw, sig, key, map[string][]byte{"filesystem": data}); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
