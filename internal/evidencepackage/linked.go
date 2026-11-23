package evidencepackage

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

// receiptGraph is a DAG, not an artificial total order: Sandbox and Compute
// can independently observe their releases after Guard settles.
var receiptGraph = []struct{ stage, parent string }{
	{"run", ""},
	{"decision", "run"},
	{"permit", "decision"},
	{"recovery", "permit"},
	{"guard_release", "recovery"},
	{"sandbox_release", "guard_release"},
	{"compute_release", "guard_release"},
}

// VerifyLinked is an opt-in, read-only extension of Verify. In addition to
// exact independent Run/fault binding, native receipt hashes, distinct owner
// signatures and fixed source revisions, it requires every downstream
// owner-signed export to commit to the exact raw SIGNED EXPORT bytes of its
// required parent. Re-encoding JSON before hashing would destroy that proof.
//
// This validates immutable receipt correlation only: signers can still lie
// about physical execution, real-time causal order or provider absence.
// Production must use separate authenticated owner journals and PEP checks.
func VerifyLinked(p Package, e Expected, keys map[string]ed25519.PublicKey, now time.Time) error {
	if err := Verify(p, e, keys, now); err != nil {
		return err
	}

	// Verify has already validated each stage and its signed bytes. This
	// second pass does not infer a source or key from the submitted package.
	rawByStage := make(map[string][]byte, len(receiptGraph))
	parentByStage := make(map[string]string, len(receiptGraph))
	for _, edge := range receiptGraph {
		parentByStage[edge.stage] = edge.parent
	}
	for _, receipt := range p.Receipts {
		if _, ok := parentByStage[receipt.Stage]; !ok {
			return reject("unknown receipt link stage")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(receipt.PayloadB64)
		if err != nil {
			return reject("invalid linked signed receipt bytes")
		}
		if _, exists := rawByStage[receipt.Stage]; exists {
			return reject("duplicate linked signed receipt stage")
		}
		rawByStage[receipt.Stage] = raw
	}
	for _, edge := range receiptGraph {
		raw, ok := rawByStage[edge.stage]
		if !ok {
			return reject("missing signed receipt in link graph")
		}
		var statement Statement
		if !StrictDecode(raw, &statement) {
			return reject("invalid linked signed statement")
		}
		if edge.parent == "" {
			if statement.ParentExportDigest != "" {
				return reject("root signed receipt must not claim a parent")
			}
			continue
		}
		upstream, ok := rawByStage[edge.parent]
		if !ok || statement.ParentExportDigest != DigestRaw(upstream) {
			return reject("signed receipt parent export digest absent or inconsistent")
		}
	}
	return nil
}
