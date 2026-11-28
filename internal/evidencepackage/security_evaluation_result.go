package evidencepackage

import "strings"

// EvaluationOutcome is a report-only verdict. It cannot grant a Permit,
// attest physical isolation, or authorize release or dispatch.
type EvaluationOutcome string

const (
	EvaluationPass EvaluationOutcome = "PASS"
	EvaluationFail EvaluationOutcome = "FAIL"
	EvaluationHold EvaluationOutcome = "HOLD"
)

// EvaluationBinding is supplied by the trusted evaluation caller, not the
// evaluated Agent. PolicyDigest identifies the exact immutable test plan.
type EvaluationBinding struct {
	TenantID      string
	RunID         string
	PolicyDigest  string
	VerifierRunID string
}

type EvaluationPlan struct {
	Binding  EvaluationBinding
	Required []string
}

type EvaluationFinding struct {
	ScenarioID     string
	Outcome        EvaluationOutcome
	EvidenceDigest string
}

type EvaluationReport struct {
	Binding  EvaluationBinding
	Findings []EvaluationFinding
}

// SummarizeEvaluation aggregates already authenticated findings for display
// and offline regression reporting only. It does not authenticate a source,
// retrieve evidence bytes, or verify that a digest matches real evidence.
// Callers must perform those checks independently; untrusted reports must
// not be used as an acceptance gate. Invalid inputs HOLD; valid recorded failures take precedence over incomplete coverage.
func SummarizeEvaluation(plan EvaluationPlan, report EvaluationReport) EvaluationOutcome {
	b := plan.Binding
	if report.Binding != b || !evaluationID(b.TenantID) || !evaluationID(b.RunID) ||
		!evaluationID(b.VerifierRunID) || !evaluationDigest(b.PolicyDigest) ||
		len(plan.Required) == 0 || len(plan.Required) > 4096 || len(report.Findings) > len(plan.Required) {
		return EvaluationHold
	}
	remaining := make(map[string]bool, len(plan.Required))
	for _, id := range plan.Required {
		if !evaluationID(id) || remaining[id] {
			return EvaluationHold
		}
		remaining[id] = true
	}
	hold, fail := false, false
	for _, finding := range report.Findings {
		if !remaining[finding.ScenarioID] || !evaluationDigest(finding.EvidenceDigest) {
			return EvaluationHold
		}
		delete(remaining, finding.ScenarioID)
		switch finding.Outcome {
		case EvaluationPass:
		case EvaluationFail:
			fail = true
		case EvaluationHold:
			hold = true
		default:
			return EvaluationHold
		}
	}
	if fail {
		return EvaluationFail
	}
	if hold || len(remaining) != 0 {
		return EvaluationHold
	}
	return EvaluationPass
}

func evaluationID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func evaluationDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, c := range value[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
