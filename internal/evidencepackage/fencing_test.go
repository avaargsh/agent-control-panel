package evidencepackage

import (
	"testing"
)

func TestEvidencePackageFencesOldAndConflictingSourceRevisions(t *testing.T) {
	f := fixturePackage(t)
	if err := Verify(f.p, f.e, f.pub, f.now); err != nil {
		t.Fatalf("fresh expected source heads must verify: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Statement)
	}{
		{"old_signed_receipt", func(s *Statement) { s.SourceRevision-- }},
		{"unexpected_future_revision", func(s *Statement) { s.SourceRevision++ }},
		{"missing_revision", func(s *Statement) { s.SourceRevision = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixturePackage(t)
			mutate(t, &f, "decision", tc.change)
			if err := Verify(f.p, f.e, f.pub, f.now); err == nil {
				t.Fatal("signed but unpinned revision accepted")
			}
		})
	}
	t.Run("independent_head_advanced", func(t *testing.T) {
		f := fixturePackage(t)
		f.e.SourceRevisions["decision"]++
		if err := Verify(f.p, f.e, f.pub, f.now); err == nil {
			t.Fatal("prior decision receipt accepted against newer independent head")
		}
	})
	t.Run("missing_expected_authority_head", func(t *testing.T) {
		f := fixturePackage(t)
		delete(f.e.SourceRevisions, "compute_release")
		if err := Verify(f.p, f.e, f.pub, f.now); err == nil {
			t.Fatal("missing independent compute head accepted")
		}
	})
	t.Run("unexpected_authority_head", func(t *testing.T) {
		f := fixturePackage(t)
		f.e.SourceRevisions["foreign_stage"] = 1
		if err := Verify(f.p, f.e, f.pub, f.now); err == nil {
			t.Fatal("unrecognized independent head accepted")
		}
	})
}

func TestReceiptHeadCASDecisionIsIdempotentAndRejectsStaleOverwrite(t *testing.T) {
	first := ReceiptHead{
		TenantID: "tenant-1", RunID: "run-1", Stage: "decision",
		Authority: "decision", Revision: 4, Digest: hash("a"),
	}
	if disposition, err := CompareReceiptHead(nil, first); err != nil || disposition != ReceiptInsert {
		t.Fatalf("initial insert: %q %v", disposition, err)
	}
	if disposition, err := CompareReceiptHead(&first, first); err != nil || disposition != ReceiptReplay {
		t.Fatalf("same digest/revision must replay: %q %v", disposition, err)
	}
	for _, tc := range []struct {
		name string
		edit func(*ReceiptHead)
	}{
		{"stale_version", func(h *ReceiptHead) { h.Revision-- }},
		{"same_revision_different_bytes", func(h *ReceiptHead) { h.Digest = hash("b") }},
		{"wrong_run", func(h *ReceiptHead) { h.RunID = "other-run" }},
		{"wrong_tenant", func(h *ReceiptHead) { h.TenantID = "other-tenant" }},
		{"wrong_authority", func(h *ReceiptHead) { h.Authority = "guard" }},
		{"invalid_digest", func(h *ReceiptHead) { h.Digest = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			incoming := first
			tc.edit(&incoming)
			if _, err := CompareReceiptHead(&first, incoming); err == nil {
				t.Fatal("unsafe receipt update accepted")
			}
		})
	}
	newer := first
	newer.Revision++
	newer.Digest = hash("b")
	if disposition, err := CompareReceiptHead(&first, newer); err != nil || disposition != ReceiptAdvance {
		t.Fatalf("monotonic new revision: %q %v", disposition, err)
	}
}
