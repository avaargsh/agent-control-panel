package evidencepackage

import (
	"crypto/ed25519"
	"time"
)

// VerifyLinked is an opt-in read-only consistency gate for owner-signed
// exported receipt dependencies. The v2 Verify API remains unchanged.
// This initial candidate will be hardened test-first before review.
func VerifyLinked(p Package, e Expected, keys map[string]ed25519.PublicKey, now time.Time) error {
	return Verify(p, e, keys, now)
}
