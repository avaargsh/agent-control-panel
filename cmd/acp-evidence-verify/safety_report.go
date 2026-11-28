package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/evidencepackage"
)

// Trust is operator-controlled and must be obtained independently of submission.
// Byte fields use standard JSON base64 encoding. These are offline review inputs.
type safetyReportTrust struct {
	Policy         []byte
	Infrastructure evidencepackage.EvaluationDimensionTrust
	Behavioral     evidencepackage.EvaluationDimensionTrust
}

type safetyReportSubmission struct {
	Infrastructure evidencepackage.EvaluationDimensionReceipt
	Behavioral     evidencepackage.EvaluationDimensionReceipt
}

// safetyReviewSummary is an unsigned audit correlation record, not a seal.
type safetyReviewSummary struct {
	Schema           string
	ReviewedAt       time.Time
	TrustDigest      string
	SubmissionDigest string
	evidencepackage.SafetyDimensionSummary
}

func readCanonicalSafetyInput(path string, limit int64, target any) (string, error) {
	raw, err := readRegular(path, limit)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return "", errors.New("invalid safety input JSON")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return "", errors.New("noncanonical safety input JSON")
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}

// runSafetyReport emits only a report summary. FAIL and HOLD return errors;
// neither this command nor a PASS can authorize execution or release.
func runSafetyReport(args []string, out io.Writer, now time.Time) error {
	flags := flag.NewFlagSet("acp-evidence-verify safety-report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	trustPath := flags.String("trust", "", "independently obtained policy and verifier trust configuration")
	submissionPath := flags.String("submission", "", "submitted signed reports and evidence")
	audit := flags.Bool("audit-summary", false, "include unsigned input digests and review time")
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		var usage bytes.Buffer
		flags.SetOutput(&usage)
		flags.Usage()
		return errors.New(usage.String())
	}
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *trustPath == "" || *submissionPath == "" {
		return errors.New("safety-report requires --trust and --submission; trust must be independently obtained")
	}
	var trust safetyReportTrust
	trustDigest, err := readCanonicalSafetyInput(*trustPath, 4<<20, &trust)
	if err != nil {
		return errors.New("invalid independent safety trust input")
	}
	var submission safetyReportSubmission
	submissionDigest, err := readCanonicalSafetyInput(*submissionPath, 52<<20, &submission)
	if err != nil {
		return errors.New("invalid safety submission input")
	}
	summary := evidencepackage.EvaluatePinnedSafetyPolicy(trust.Policy, trust.Infrastructure, submission.Infrastructure, trust.Behavioral, submission.Behavioral, now)
	var result any = summary
	if *audit {
		result = safetyReviewSummary{Schema: "acp.safety-review-summary/v1", ReviewedAt: now.UTC(), TrustDigest: trustDigest, SubmissionDigest: submissionDigest, SafetyDimensionSummary: summary}
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return errors.New("unable to write safety report summary")
	}
	if summary.Overall != evidencepackage.EvaluationPass {
		return errors.New("offline safety report did not pass")
	}
	return nil
}
