package evidencepackage

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func archiveFixture(t *testing.T) (fixture, []byte, []byte, ArchiveSeal, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	f := fixturePackage(t)
	rawPackage, err := json.Marshal(f.p)
	if err != nil {
		t.Fatal(err)
	}
	rawExpected, err := json.Marshal(f.e)
	if err != nil {
		t.Fatal(err)
	}
	archivePublic, archivePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stmt := ArchiveStatement{
		Schema: ArchiveSchema, ArchiveID: "archive-1",
		CapturedAt: f.now, SealedAt: f.now.Add(30 * time.Second),
		PackageDigest: DigestRaw(rawPackage), ExpectedDigest: DigestRaw(rawExpected),
	}
	seal := signArchiveFixture(t, stmt, archivePrivate)
	return f, rawPackage, rawExpected, seal, archivePublic, archivePrivate
}

func signArchiveFixture(t *testing.T, statement ArchiveStatement, key ed25519.PrivateKey) ArchiveSeal {
	t.Helper()
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	return ArchiveSeal{
		PayloadB64: base64.StdEncoding.EncodeToString(raw),
		SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(ArchiveDomain), raw...))),
	}
}

func TestArchiveProofAllowsHistoricRereadOnlyWithIndependentSeal(t *testing.T) {
	f, pkg, expected, seal, archiveKey, _ := archiveFixture(t)
	later := f.now.Add(24 * time.Hour)
	if err := Verify(f.p, f.e, f.pub, later); err == nil {
		t.Fatal("live temporal gate accepted a day-old observation")
	}
	if err := VerifyArchive(pkg, expected, seal, f.pub, archiveKey, later); err != nil {
		t.Fatalf("independently attested historical evidence rejected: %v", err)
	}
}

func TestArchiveRejectsSignatureSubstitutionAndPayloadDrift(t *testing.T) {
	cases := []struct {
		name string
		edit func(*testing.T, *fixture, *[]byte, *[]byte, *ArchiveSeal, *ed25519.PublicKey)
	}{
		{"changed_package", func(_ *testing.T, _ *fixture, p *[]byte, _ *[]byte, _ *ArchiveSeal, _ *ed25519.PublicKey) {
			*p = append(append([]byte(nil), (*p)...), ' ')
		}},
		{"changed_expected", func(_ *testing.T, _ *fixture, _ *[]byte, e *[]byte, _ *ArchiveSeal, _ *ed25519.PublicKey) {
			*e = append(append([]byte(nil), (*e)...), ' ')
		}},
		{"wrong_archive_key", func(t *testing.T, _ *fixture, _ *[]byte, _ *[]byte, _ *ArchiveSeal, key *ed25519.PublicKey) {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			*key = pub
		}},
		{"service_key_reused_as_archive", func(_ *testing.T, f *fixture, _ *[]byte, _ *[]byte, _ *ArchiveSeal, key *ed25519.PublicKey) {
			*key = f.pub["guard"]
		}},
		{"missing_signature", func(_ *testing.T, _ *fixture, _ *[]byte, _ *[]byte, s *ArchiveSeal, _ *ed25519.PublicKey) {
			s.SignatureB64 = ""
		}},
		{"missing_seal_body", func(_ *testing.T, _ *fixture, _ *[]byte, _ *[]byte, s *ArchiveSeal, _ *ed25519.PublicKey) {
			s.PayloadB64 = ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, pkg, expected, seal, archiveKey, _ := archiveFixture(t)
			tc.edit(t, &f, &pkg, &expected, &seal, &archiveKey)
			if err := VerifyArchive(pkg, expected, seal, f.pub, archiveKey, f.now.Add(time.Hour)); err == nil {
				t.Fatal("untrusted archive substitution accepted")
			}
		})
	}
}

func TestArchiveRejectsBackdatedOrFutureSignedCapture(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*ArchiveStatement)
	}{
		{"capture_too_old_for_fault", func(s *ArchiveStatement) { s.CapturedAt = s.CapturedAt.Add(time.Hour) }},
		{"capture_before_fault", func(s *ArchiveStatement) { s.CapturedAt = s.CapturedAt.Add(-time.Hour) }},
		{"capture_after_sealing", func(s *ArchiveStatement) { s.CapturedAt = s.SealedAt.Add(time.Minute) }},
		{"late_sealing", func(s *ArchiveStatement) { s.SealedAt = s.SealedAt.Add(10 * time.Minute) }},
		{"future_sealing", func(s *ArchiveStatement) { s.SealedAt = s.SealedAt.Add(48 * time.Hour) }},
		{"missing_archive_id", func(s *ArchiveStatement) { s.ArchiveID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, pkg, expected, _, archiveKey, archivePrivate := archiveFixture(t)
			stmt := ArchiveStatement{
				Schema: ArchiveSchema, ArchiveID: "archive-1",
				CapturedAt: f.now, SealedAt: f.now.Add(30 * time.Second),
				PackageDigest: DigestRaw(pkg), ExpectedDigest: DigestRaw(expected),
			}
			tc.edit(&stmt)
			seal := signArchiveFixture(t, stmt, archivePrivate)
			if err := VerifyArchive(pkg, expected, seal, f.pub, archiveKey, f.now.Add(24*time.Hour)); err == nil {
				t.Fatal("invalid but signed capture time accepted")
			}
		})
	}
}

func TestArchiveRejectsDuplicateSignedJSONKeys(t *testing.T) {
	f, pkg, expected, seal, archiveKey, archivePrivate := archiveFixture(t)
	raw, err := base64.StdEncoding.DecodeString(seal.PayloadB64)
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := strings.Replace(string(raw), `"archive_id":"archive-1"`, `"archive_id":"other","archive_id":"archive-1"`, 1)
	if ambiguous == string(raw) {
		t.Fatal("fixture did not contain original archive_id")
	}
	seal.PayloadB64 = base64.StdEncoding.EncodeToString([]byte(ambiguous))
	seal.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(archivePrivate, append([]byte(ArchiveDomain), []byte(ambiguous)...)))
	if err := VerifyArchive(pkg, expected, seal, f.pub, archiveKey, f.now.Add(time.Hour)); err == nil {
		t.Fatal("ambiguously signed capture accepted")
	}
}
