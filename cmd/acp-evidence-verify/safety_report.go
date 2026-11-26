package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
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

func readCanonicalSafetyInput(path string, limit int64, target any) error {
	raw, err := readRegular(path, limit)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return errors.New("invalid safety input JSON")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("noncanonical safety input JSON")
	}
	return nil
}

// runSafetyReport emits only a report summary. FAIL and HOLD return errors;
// neither this command nor a PASS can authorize execution or release.
func runSafetyReport(args []string, out io.Writer, now time.Time) error {
	flags := flag.NewFlagSet("acp-evidence-verify safety-report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	trustPath := flags.String("trust", "", "independently obtained policy and verifier trust configuration")
	submissionPath := flags.String("submission", "", "submitted signed reports and evidence")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *trustPath == "" || *submissionPath == "" {
		return errors.New("safety-report requires --trust and --submission; trust must be independently obtained")
	}
	var trust safetyReportTrust
	if err := readCanonicalSafetyInput(*trustPath, 4<<20, &trust); err != nil {
		return errors.New("invalid independent safety trust input")
	}
	var submission safetyReportSubmission
	if err := readCanonicalSafetyInput(*submissionPath, 52<<20, &submission); err != nil {
		return errors.New("invalid safety submission input")
	}
	summary := evidencepackage.EvaluatePinnedSafetyPolicy(trust.Policy, trust.Infrastructure, submission.Infrastructure, trust.Behavioral, submission.Behavioral, now)
	if err := json.NewEncoder(out).Encode(summary); err != nil {
		return errors.New("unable to write safety report summary")
	}
	if summary.Overall != evidencepackage.EvaluationPass {
		return errors.New("offline safety report did not pass")
	}
	return nil
}
