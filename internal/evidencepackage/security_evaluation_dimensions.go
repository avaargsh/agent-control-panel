package evidencepackage

import (
	"crypto/ed25519"
	"time"
)

// EvaluationDimensionTrust must be independently obtained by the caller for
// the named dimension; never construct it from the receipt being evaluated.
// The caller owns the mapping of scenario IDs to each safety dimension.
type EvaluationDimensionTrust struct {
	Plan   EvaluationPlan
	Window EvaluationReceiptWindow
	Key    ed25519.PublicKey
}

type EvaluationDimensionReceipt struct {
	Raw       []byte
	Signature []byte
	Evidence  map[string][]byte
}

// SafetyDimensionSummary is a report-only result, not a release gate.
type SafetyDimensionSummary struct {
	Infrastructure EvaluationOutcome
	Behavioral     EvaluationOutcome
	Overall        EvaluationOutcome
}

// EvaluateSafetyDimensions checks two separately pinned reports for the same
// Tenant/Run/shared policy. Neither dimension substitutes for the other. Distinct verifier
// run IDs and disjoint required scenario sets prevent accidental double
// counting. A verifier service may sign both reports; its independence from
// the evaluated Agent and the correctness of the policy remain external.
// This function never executes scenarios or authorizes protected effects.
func EvaluateSafetyDimensions(infra EvaluationDimensionTrust, infraReceipt EvaluationDimensionReceipt, behavior EvaluationDimensionTrust, behaviorReceipt EvaluationDimensionReceipt, now time.Time) SafetyDimensionSummary {
	hold := SafetyDimensionSummary{EvaluationHold, EvaluationHold, EvaluationHold}
	a, b := infra.Plan.Binding, behavior.Plan.Binding
	if a.TenantID != b.TenantID || a.RunID != b.RunID || a.PolicyDigest != b.PolicyDigest || a.VerifierRunID == b.VerifierRunID {
		return hold
	}
	seen := make(map[string]bool)
	for _, plan := range []EvaluationPlan{infra.Plan, behavior.Plan} {
		binding := plan.Binding
		if !evaluationID(binding.TenantID) || !evaluationID(binding.RunID) || !evaluationID(binding.VerifierRunID) || !evaluationDigest(binding.PolicyDigest) || len(plan.Required) == 0 || len(plan.Required) > 4096 {
			return hold
		}
		for _, id := range plan.Required {
			if !evaluationID(id) || seen[id] {
				return hold
			}
			seen[id] = true
		}
	}
	verify := func(trust EvaluationDimensionTrust, receipt EvaluationDimensionReceipt) EvaluationOutcome {
		return VerifyPinnedEvaluationReport(trust.Plan, trust.Window, now, receipt.Raw, receipt.Signature, trust.Key, receipt.Evidence)
	}
	result := SafetyDimensionSummary{Infrastructure: verify(infra, infraReceipt), Behavioral: verify(behavior, behaviorReceipt), Overall: EvaluationHold}
	if result.Infrastructure == EvaluationFail || result.Behavioral == EvaluationFail {
		result.Overall = EvaluationFail
	} else if result.Infrastructure == EvaluationPass && result.Behavioral == EvaluationPass {
		result.Overall = EvaluationPass
	}
	return result
}
