package evidencepackage

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

const SafetyEvaluationPolicySchema = "acp.security-evaluation-policy/v1"
const maxSafetyEvaluationPolicyBytes = 2 << 20

// SafetyEvaluationPolicy is an offline immutable scenario manifest, not a
// policy registry or an execution authorization. Its ordering is significant.
type SafetyEvaluationPolicy struct {
	Schema         string
	Version        string
	Infrastructure []string
	Behavioral     []string
}

// EvaluatePinnedSafetyPolicy validates the exact policy manifest and both
// required scenario lists before verifying the signed reports. Both plan
// digests and trust inputs must originate from trusted independent policy
// configuration, not the submitted manifest or evaluated Agent. The digest
// does not prove the policy is sufficient, current or externally approved.
// This entry point is for offline reporting, never protected-effect approval.
func EvaluatePinnedSafetyPolicy(raw []byte, infra EvaluationDimensionTrust, infraReceipt EvaluationDimensionReceipt, behavior EvaluationDimensionTrust, behaviorReceipt EvaluationDimensionReceipt, now time.Time) SafetyDimensionSummary {
	hold := SafetyDimensionSummary{EvaluationHold, EvaluationHold, EvaluationHold}
	if len(raw) == 0 || len(raw) > maxSafetyEvaluationPolicyBytes {
		return hold
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	if infra.Plan.Binding.PolicyDigest != digest || behavior.Plan.Binding.PolicyDigest != digest {
		return hold
	}
	var policy SafetyEvaluationPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return hold
	}
	canonical, err := json.Marshal(policy)
	if err != nil || !bytes.Equal(canonical, raw) || policy.Schema != SafetyEvaluationPolicySchema || !evaluationID(policy.Version) ||
		!slices.Equal(policy.Infrastructure, infra.Plan.Required) || !slices.Equal(policy.Behavioral, behavior.Plan.Required) {
		return hold
	}
	return EvaluateSafetyDimensions(infra, infraReceipt, behavior, behaviorReceipt, now)
}
