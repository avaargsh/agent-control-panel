package evidencepackage

import (
	"encoding/base64"
	"fmt"
	"testing"
)

// These links are signed by each receiving source, not invented by the
// verifier. Two release owners both depend on Guard settlement; their
// physical release operations need not be serial with one another.
func linkedFixture(t *testing.T) fixture {
	t.Helper()
	f := fixturePackage(t)
	parent := map[string]string{
		"run": "", "decision": "run", "permit": "decision",
		"recovery": "permit", "guard_release": "recovery",
		"sandbox_release": "guard_release", "compute_release": "guard_release",
	}
	signedPayloads := make(map[string][]byte, len(stages))
	for i, r := range f.p.Receipts {
		stage := r.Stage
		if _, ok := parent[stage]; !ok {
			t.Fatalf("unrecognized fixture stage: %q", stage)
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(r.PayloadB64)
		if err != nil {
			t.Fatal(err)
		}
		var statement Statement
		if !StrictDecode(raw, &statement) {
			t.Fatal("bad original statement")
		}
		if prev := parent[stage]; prev != "" {
			predecessor, exists := signedPayloads[prev]
			if !exists {
				t.Fatalf("upstream signed export %q missing before %q", prev, stage)
			}
			statement.ParentExportDigest = DigestRaw(predecessor)
		}
		f.p.Receipts[i] = signStatement(t, statement, f.priv[r.Authority])
		signedPayloads[stage], err = base64.StdEncoding.Strict().DecodeString(f.p.Receipts[i].PayloadB64)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestLinkedEvidenceValidForkedReleaseGraph(t *testing.T) {
	f := linkedFixture(t)
	if err := VerifyLinked(f.p, f.e, f.pub, f.now); err != nil {
		t.Fatalf("independently signed same-Run receipt graph rejected: %v", err)
	}
}

func TestLinkedEvidenceRejectsSignedButReboundParentGraph(t *testing.T) {
	stagesToAlter := []string{
		"run", "decision", "permit", "recovery",
		"guard_release", "sandbox_release", "compute_release",
	}
	for _, stage := range stagesToAlter {
		for _, corruption := range []string{"missing", "wrong_digest"} {
			if stage == "run" && corruption == "missing" {
				continue // The root must have no predecessor.
			}
			t.Run(fmt.Sprintf("%s/%s", stage, corruption), func(t *testing.T) {
				f := linkedFixture(t)
				mutate(t, &f, stage, func(s *Statement) {
					if corruption == "missing" {
						s.ParentExportDigest = ""
					} else {
						s.ParentExportDigest = hash("f")
					}
				})
				// The v2 verifier deliberately cannot detect a tampered
				// optional link. The dedicated linked gate MUST refuse
				// this even though all owner signatures are valid.
				if err := Verify(f.p, f.e, f.pub, f.now); err != nil {
					t.Fatalf("precondition: base v2 signed validator rejected: %v", err)
				}
				if err := VerifyLinked(f.p, f.e, f.pub, f.now); err == nil {
					t.Fatalf("owner-signed %s parent link %s passed", stage, corruption)
				}
			})
		}
	}
}

func TestLinkedEvidenceRejectsWrongSiblingAsComputeParent(t *testing.T) {
	f := linkedFixture(t)
	var sandboxRaw []byte
	for _, r := range f.p.Receipts {
		if r.Stage == "sandbox_release" {
			var err error
			sandboxRaw, err = base64.StdEncoding.Strict().DecodeString(r.PayloadB64)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(sandboxRaw) == 0 {
		t.Fatal("missing sibling source")
	}
	mutate(t, &f, "compute_release", func(s *Statement) {
		s.ParentExportDigest = DigestRaw(sandboxRaw)
	})
	if err := VerifyLinked(f.p, f.e, f.pub, f.now); err == nil {
		t.Fatal("compute release incorrectly depended on sandbox sibling, not Guard settlement")
	}
}
