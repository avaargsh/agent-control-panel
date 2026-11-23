package evidencepackage

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/postfault"
)

// A valid signature proves the owner made an observation, not that the
// protected operation had already reached the required recovery stage.
func shiftSignedPostfaultObservation(t *testing.T, f *fixture, authority string, when time.Time) {
	t.Helper()
	raw, err := base64.StdEncoding.Strict().DecodeString(f.p.PostfaultB64)
	if err != nil {
		t.Fatal(err)
	}
	var bundle postfault.Bundle
	if !postfault.StrictDecode(raw, &bundle) {
		t.Fatal("invalid original postfault fixture")
	}
	found := false
	for i, receipt := range bundle.Receipts {
		if receipt.Authority != authority || receipt.Phase != "after_recovery" {
			continue
		}
		observationRaw, err := base64.StdEncoding.Strict().DecodeString(receipt.PayloadB64)
		if err != nil {
			t.Fatal(err)
		}
		var observation postfault.Observation
		if !postfault.StrictDecode(observationRaw, &observation) {
			t.Fatal("invalid signed observation fixture")
		}
		observation.ObservedAt = when
		updatedRaw, err := json.Marshal(observation)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Receipts[i].PayloadB64 = base64.StdEncoding.EncodeToString(updatedRaw)
		bundle.Receipts[i].SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(
			f.priv[authority], append([]byte(postfault.SignatureDomain), updatedRaw...)))
		found = true
		break
	}
	if !found {
		t.Fatalf("missing postfault observation for %s", authority)
	}
	updatedBundle, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	f.p.PostfaultB64 = base64.StdEncoding.EncodeToString(updatedBundle)

	// Assert the postfault gate itself still accepts these validly signed,
	// fresh and internally continuous owner observations. A rejection below
	// must be caused by missing cross-service settlement ordering.
	keys := make(map[string]ed25519.PublicKey)
	for _, name := range []string{"runtime", "sandbox", "agentd", "guard"} {
		keys[name] = f.pub[name]
	}
	if err := postfault.Verify(bundle, keys, f.now); err != nil {
		t.Fatalf("test precondition: independently signed postfault proof rejected: %v", err)
	}
}

func TestEvidencePackageRejectsSettlementBeforeSignedRecoveryObservations(t *testing.T) {
	for _, owner := range []string{"runtime", "agentd", "guard", "sandbox"} {
		t.Run(owner, func(t *testing.T) {
			f := fixturePackage(t)
			if err := Verify(f.p, f.e, f.pub, f.now); err != nil {
				t.Fatalf("original signed lifecycle must be valid: %v", err)
			}
			// The Guard settlement is at fault+4s; the independent
			// post-recovery observation is moved to fault+7s, after even
			// the downstream Sandbox/Compute release receipts.
			shiftSignedPostfaultObservation(t, &f, owner, f.e.Fault.At.Add(7*time.Second))
			if err := Verify(f.p, f.e, f.pub, f.now); err == nil ||
				!strings.Contains(err.Error(), "settlement predates signed postfault recovery proof") {
				t.Fatalf("G03/G04 must reject premature settlement for %s, got: %v", owner, err)
			}
		})
	}
}

func TestEvidencePackageRejectsRecoveredRunBeforeSourceRecoveryProof(t *testing.T) {
	for _, owner := range []string{"runtime", "agentd", "guard", "sandbox"} {
		t.Run(owner, func(t *testing.T) {
			f := fixturePackage(t)
			// Runtime's RECOVERED lifecycle statement is fault+3s; all
			// required owners report an independently signed observation
			// at fault+3.5s. Guard settlement at fault+4s is still after
			// that observation, so this specifically tests G05 recovery
			// ordering rather than the G03/G04 settlement fence.
			shiftSignedPostfaultObservation(t, &f, owner, f.e.Fault.At.Add(3500*time.Millisecond))
			if err := Verify(f.p, f.e, f.pub, f.now); err == nil ||
				!strings.Contains(err.Error(), "recovered Run predates signed postfault source proof") {
				t.Fatalf("G05 must reject premature recovery for %s, got: %v", owner, err)
			}
		})
	}
}

func TestEvidencePackageAcceptsSourceProofBeforeRecoveredRunAndSettlement(t *testing.T) {
	f := fixturePackage(t)
	for _, owner := range []string{"runtime", "agentd", "guard", "sandbox"} {
		shiftSignedPostfaultObservation(t, &f, owner, f.e.Fault.At.Add(2500*time.Millisecond))
	}
	if err := Verify(f.p, f.e, f.pub, f.now); err != nil {
		t.Fatalf("valid signed recovery -> recovered Run -> settlement ordering rejected: %v", err)
	}
}

func TestEvidencePackageRejectsSignedLifecycleStagesOutOfOrder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage string
	}{
		{"decision_precedes_accepted_run", "decision"},
		{"permit_precedes_accepted_decision", "permit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixturePackage(t)
			// All three owner receipts are normally fault-10s. Moving a
			// source-signed Decision/Permit backward preserves signatures,
			// source revisions, and pre-fault validity, but breaks the
			// necessary Run -> Decision -> Permit dependency order.
			mutate(t, &f, tc.stage, func(s *Statement) {
				s.ObservedAt = f.e.Fault.At.Add(-15 * time.Second)
			})
			if err := Verify(f.p, f.e, f.pub, f.now); err == nil ||
				!strings.Contains(err.Error(), "signed Run, Decision and Permit stages out of order") {
				t.Fatalf("G01/G03 must reject signed causal inversion, got: %v", err)
			}
		})
	}
}
