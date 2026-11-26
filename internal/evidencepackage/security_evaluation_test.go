package evidencepackage

import (
	"errors"
	"testing"
)

// The generated fixture verifies offline consistency only. No synthetic
// receipt is deployment evidence or permission to execute a command.
func TestSecurityEvaluationRequiresCompleteEvidence(t *testing.T) {
	baseline := linkedFixture(t)
	if err := VerifyLinked(baseline.p, baseline.e, baseline.pub, baseline.now); err != nil {
		t.Fatalf("complete local fixture must verify: %v", err)
	}

	for _, required := range stages {
		t.Run("missing-receipt/"+required.stage, func(t *testing.T) {
			f := linkedFixture(t)
			kept := make([]Receipt, 0, len(f.p.Receipts)-1)
			for _, receipt := range f.p.Receipts {
				if receipt.Stage != required.stage {
					kept = append(kept, receipt)
				}
			}
			if len(kept) != len(f.p.Receipts)-1 {
				t.Fatal("fixture must contain exactly one required receipt")
			}
			f.p.Receipts = kept
			if err := VerifyLinked(f.p, f.e, f.pub, f.now); !errors.Is(err, ErrUnverified) {
				t.Fatalf("missing required receipt must remain unverified: %v", err)
			}
		})
		t.Run("missing-independent-revision/"+required.stage, func(t *testing.T) {
			f := linkedFixture(t)
			delete(f.e.SourceRevisions, required.stage)
			if err := VerifyLinked(f.p, f.e, f.pub, f.now); !errors.Is(err, ErrUnverified) {
				t.Fatalf("missing independent revision must remain unverified: %v", err)
			}
		})
	}
	for _, authority := range []string{"acp", "decision", "guard", "runtime", "sandbox", "agentd", "compute"} {
		t.Run("missing-trust-root/"+authority, func(t *testing.T) {
			f := linkedFixture(t)
			delete(f.pub, authority)
			if err := VerifyLinked(f.p, f.e, f.pub, f.now); !errors.Is(err, ErrUnverified) {
				t.Fatalf("missing independent trust input must remain unverified: %v", err)
			}
		})
	}
}
