package evidencepackage

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

// ArchiveSchema and ArchiveDomain identify the independent capture-time
// attestation. Neither ACP nor this verifier may issue this attestation.
const (
	ArchiveSchema = "acp.evidence-archive-seal/v1"
	ArchiveDomain = "acp.evidence-archive-seal/v1\\x00"
	maxArchiveSealBytes = 4096
	maxArchivePackageBytes = 256 << 10
	maxArchiveExpectedBytes = 8192
	maxArchiveSealDelay = 2 * time.Minute
)

// ArchiveStatement is a signed assertion by a separately trusted archival
// service. CapturedAt must reflect a source-observed live verification instant;
// it is NOT a self-reported time from a Run or a model-generated payload.
// Signing alone cannot prevent a compromised issuer from backdating: real
// deployment also requires independent timestamp logging/notarization.
type ArchiveStatement struct {
	Schema string `json:"schema"`
	ArchiveID string `json:"archive_id"`
	CapturedAt time.Time `json:"captured_at"`
	SealedAt time.Time `json:"sealed_at"`
	PackageDigest string `json:"package_digest"`
	ExpectedDigest string `json:"expected_digest"`
}

// ArchiveSeal retains the exact signed bytes, not a reconstructed JSON view.
// The raw package and expected bindings are independently hash-pinned.
type ArchiveSeal struct {
	PayloadB64 string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
}

// VerifyArchive is an OFFLINE consistency re-verification, NOT a live Permit
// authorization. The seven owner keys and separate archival public key MUST
// be supplied out of band, never inferred from submitted evidence. Freshness
// is checked at the independently attested original capture instant; the
// externally trusted archive issuer is responsible for time provenance.
// Live decisions must continue to call Verify(..., realNow) instead.
func VerifyArchive(rawPackage, rawExpected []byte, seal ArchiveSeal, keys map[string]ed25519.PublicKey, archiveKey ed25519.PublicKey, now time.Time) error {
	if len(rawPackage) == 0 || len(rawPackage) > maxArchivePackageBytes ||
		len(rawExpected) == 0 || len(rawExpected) > maxArchiveExpectedBytes ||
		len(archiveKey) != ed25519.PublicKeySize || !keysValid(keys) || now.IsZero() {
		return reject("invalid bounded archive inputs or trust anchors")
	}
	for _, ownerKey := range keys {
		if bytes.Equal(archiveKey, ownerKey) {
			return reject("archive issuer must not reuse service authority key")
		}
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(seal.PayloadB64)
	if err != nil || len(payload) == 0 || len(payload) > maxArchiveSealBytes {
		return reject("invalid bounded archive seal bytes")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(seal.SignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(archiveKey, append([]byte(ArchiveDomain), payload...), sig) {
		return reject("missing independent archival issuer signature")
	}
	var attested ArchiveStatement
	if !StrictDecode(payload, &attested) || attested.Schema != ArchiveSchema ||
		!identifier(attested.ArchiveID) || attested.CapturedAt.IsZero() ||
		attested.SealedAt.IsZero() || attested.CapturedAt.After(attested.SealedAt) ||
		attested.SealedAt.Sub(attested.CapturedAt) > maxArchiveSealDelay ||
		attested.SealedAt.After(now) ||
		!digest(attested.PackageDigest) || !digest(attested.ExpectedDigest) ||
		attested.PackageDigest != DigestRaw(rawPackage) ||
		attested.ExpectedDigest != DigestRaw(rawExpected) {
		return reject("archive capture time or original bytes are not independently pinned")
	}
	var pkg Package
	var expected Expected
	if !StrictDecode(rawPackage, &pkg) || !StrictDecode(rawExpected, &expected) {
		return reject("invalid archived original JSON")
	}
	// This deliberately does not weaken live freshness checks or verify
	// current Guard permissions. It only tests that the original observations
	// were valid at the archival issuer's independently attested capture time.
	return Verify(pkg, expected, keys, attested.CapturedAt)
}

// DecodeArchiveSeal allows CLI callers to enforce strict JSON parsing of
// archived attestation envelopes before calling VerifyArchive.
func DecodeArchiveSeal(raw []byte) (ArchiveSeal, bool) {
	var seal ArchiveSeal
	if len(raw) == 0 || len(raw) > maxArchiveSealBytes ||
		!StrictDecode(raw, &seal) {
		return ArchiveSeal{}, false
	}
	return seal, true
}

var _ = json.Valid
