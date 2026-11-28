package evidencepackage

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"
)

// EvaluationReceiptWindow is an independently obtained immutable report
// reference and its allowed review window. It must not be derived from the
// submitted report or Agent-controlled metadata.
type EvaluationReceiptWindow struct {
	ReportDigest string
	NotBefore    time.Time
	ExpiresAt    time.Time
}

// VerifyPinnedEvaluationReport checks the exact report bytes and the trusted
// review window before signature and evidence verification. The clock, pin
// and window must come from trusted callers. This is read-only: repeating the
// same review within the window is allowed. Durable single-use consumption,
// revocation and source observation time are outside this function's scope.
func VerifyPinnedEvaluationReport(plan EvaluationPlan, window EvaluationReceiptWindow, now time.Time, raw, signature []byte, trustedKey ed25519.PublicKey, evidence map[string][]byte) EvaluationOutcome {
	if now.IsZero() || window.NotBefore.IsZero() || window.ExpiresAt.IsZero() ||
		!window.NotBefore.Before(window.ExpiresAt) || now.Before(window.NotBefore) || !now.Before(window.ExpiresAt) ||
		len(raw) == 0 || len(raw) > maxSignedEvaluationReportBytes || !evaluationDigest(window.ReportDigest) ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != window.ReportDigest {
		return EvaluationHold
	}
	return VerifySignedEvaluationReport(plan, raw, signature, trustedKey, evidence)
}
