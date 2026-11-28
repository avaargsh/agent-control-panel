package evidencepackage

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
)

const EvaluationReportSignatureDomain = "acp.security-evaluation-report/v1\x00"
const maxSignedEvaluationReportBytes = 2 << 20

// VerifySignedEvaluationReport verifies a canonical report signed by a
// caller-pinned verifier key, then checks its binding and evidence bytes.
// The caller must independently obtain the immutable plan and select the
// trusted key for this verifier run. It must not derive either from the report.
// This is an offline reporting verdict, not proof of real isolation, signer
// independence, freshness, or authority to execute or release resources.
func VerifySignedEvaluationReport(plan EvaluationPlan, raw, signature []byte, trustedKey ed25519.PublicKey, evidence map[string][]byte) EvaluationOutcome {
	if len(raw) == 0 || len(raw) > maxSignedEvaluationReportBytes ||
		len(trustedKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(trustedKey, append([]byte(EvaluationReportSignatureDomain), raw...), signature) {
		return EvaluationHold
	}
	var report EvaluationReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return EvaluationHold
	}
	canonical, err := json.Marshal(report)
	if err != nil || !bytes.Equal(raw, canonical) {
		return EvaluationHold
	}
	return SummarizeEvaluationWithEvidence(plan, report, evidence)
}
