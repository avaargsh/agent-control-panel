package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ep "github.com/avaargsh/agent-control-panel/internal/evidencepackage"
)

func TestSafetyReportCLI(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	checkSafetyReportCases(t, now, func(t *testing.T, args []string) ([]byte, error) {
		var out bytes.Buffer
		err := runSafetyReport(args, &out, now)
		return out.Bytes(), err
	})
}

func TestSafetyReportBinary(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "acp-evidence-verify")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build actual command: %v\n%s", err, out)
	}
	now := time.Now().UTC().Add(-time.Minute)
	checkSafetyReportCases(t, now, func(t *testing.T, args []string) ([]byte, error) {
		cmd := exec.Command(bin, append([]string{"safety-report"}, args...)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !strings.Contains(stderr.String(), "SAFETY REPORT BLOCKED:") {
				t.Fatalf("unexpected process failure: %v, %s", err, stderr.String())
			}
		} else if stderr.Len() != 0 {
			t.Fatalf("unexpected success stderr: %s", stderr.String())
		}
		return out, err
	})
}

func checkSafetyReportCases(t *testing.T, now time.Time, invoke func(*testing.T, []string) ([]byte, error)) {
	t.Helper()
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
		{"expired", ep.EvaluationPass, func(a *safetyReportTrust, _ *safetyReportSubmission) {
			a.Behavioral.Window.NotBefore = now.Add(-time.Hour)
			a.Behavioral.Window.ExpiresAt = now.Add(-time.Second)
		}, ep.EvaluationHold},
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
			out, err := invoke(t, []string{"--trust", tp, "--submission", sp})
			if (err == nil) != (tc.want == ep.EvaluationPass) {
				t.Fatalf("unexpected error %v", err)
			}
			var summary ep.SafetyDimensionSummary
			if err := json.Unmarshal(out, &summary); err != nil || summary.Overall != tc.want {
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

func TestSafetyReportHelpIsNotVerification(t *testing.T) {
	for _, arg := range []string{"--help", "-h"} {
		t.Run(arg, func(t *testing.T) {
			var out bytes.Buffer
			err := runSafetyReport([]string{arg}, &out, time.Now())
			if err == nil || out.Len() != 0 || !strings.Contains(err.Error(), "Usage of acp-evidence-verify safety-report") || !strings.Contains(err.Error(), "-trust") || !strings.Contains(err.Error(), "-submission") {
				t.Fatalf("help must describe inputs without verification success: %v", err)
			}
		})
	}
}

func TestSafetyReportAuditSummary(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	checkSafetyReportCases(t, now, func(t *testing.T, args []string) ([]byte, error) {
		var out bytes.Buffer
		err := runSafetyReport(append(args, "--audit-summary"), &out, now)
		var audit struct {
			Schema           string
			ReviewedAt       time.Time
			TrustDigest      string
			SubmissionDigest string
		}
		if decodeErr := json.Unmarshal(out.Bytes(), &audit); decodeErr != nil {
			t.Fatalf("missing structured audit summary: %v", decodeErr)
		}
		if audit.Schema != "acp.safety-review-summary/v1" || !audit.ReviewedAt.Equal(now) {
			t.Fatalf("incorrect audit schema or review time: %+v", audit)
		}
		for _, pair := range []struct{ path, digest string }{{args[1], audit.TrustDigest}, {args[3], audit.SubmissionDigest}} {
			raw, readErr := os.ReadFile(pair.path)
			if readErr != nil || pair.digest != fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) {
				t.Fatalf("audit digest must bind original file bytes: %v", readErr)
			}
		}
		return out.Bytes(), err
	})
}
