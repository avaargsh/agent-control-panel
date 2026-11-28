package evidencepackage

import (
	"crypto/sha256"
	"fmt"
)

const maxEvaluationEvidenceBytes = 64 << 10
const maxEvaluationEvidenceTotalBytes = 16 << 20

// SummarizeEvaluationWithEvidence checks that the supplied original evidence
// bytes match the findings before aggregating them for offline reporting.
// It does not authenticate the verifier or attest the truth of the findings.
// The caller must independently authenticate the report and evidence source.
// No result grants execution, release, or production acceptance authority.
func SummarizeEvaluationWithEvidence(plan EvaluationPlan, report EvaluationReport, evidence map[string][]byte) EvaluationOutcome {
	outcome := SummarizeEvaluation(plan, report)
	if outcome == EvaluationHold || len(evidence) != len(report.Findings) {
		return EvaluationHold
	}
	total := 0
	for _, finding := range report.Findings {
		raw, ok := evidence[finding.ScenarioID]
		if !ok || len(raw) == 0 || len(raw) > maxEvaluationEvidenceBytes {
			return EvaluationHold
		}
		total += len(raw)
		if total > maxEvaluationEvidenceTotalBytes || fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != finding.EvidenceDigest {
			return EvaluationHold
		}
	}
	return outcome
}
