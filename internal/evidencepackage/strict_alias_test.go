package evidencepackage

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestEvidenceStrictDecodeRejectsCaseFoldedKeys(t *testing.T) {
	type status struct {
		Status string `json:"status"`
	}
	raw := []byte(`{"status":"UNKNOWN","STATUS":"EXITED"}`)
	var actual status
	if err := json.Unmarshal(raw, &actual); err != nil || actual.Status != "EXITED" {
		t.Fatalf("case-fold alias fixture not exercised: status=%q err=%v", actual.Status, err)
	}
	for _, raw := range []string{
		`{"status":"UNKNOWN","STATUS":"EXITED"}`,
		`{"subject":{"run_id":"run-1","RUN_ID":"other-run"}}`,
		`{"permit_epoch":1,"PERMIT_EPOCH":2}`,
		`{"status":"UNKNOWN","\u0053tatus":"EXITED"}`,
	} {
		var out map[string]any
		if StrictDecode([]byte(raw), &out) {
			t.Fatalf("case-folded duplicate evidence key accepted: %s", raw)
		}
	}
	var valid map[string]any
	if !StrictDecode([]byte(`{"status":"UNKNOWN","source":"agentd.inspect"}`), &valid) {
		t.Fatal("distinct evidence keys must be accepted")
	}
}

func TestEvidencePackageRejectsResignedCaseFoldedStatus(t *testing.T) {
	f := fixturePackage(t)
	for i, r := range f.p.Receipts {
		if r.Stage != "run" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(r.PayloadB64)
		if err != nil {
			t.Fatal(err)
		}
		// This remains syntactically valid and its last status value is
		// ACCEPTED; ordinary JSON unmarshalling and signature verification
		// both succeed despite an ambiguous status alias.
		ambiguous := strings.Replace(string(raw), `"status":"ACCEPTED"`,
			`"STATUS":"DENIED","status":"ACCEPTED"`, 1)
		if ambiguous == string(raw) || !json.Valid([]byte(ambiguous)) {
			t.Fatal("signed fixture did not contain accepted status")
		}
		var decoded Statement
		if err := json.Unmarshal([]byte(ambiguous), &decoded); err != nil || decoded.Status != "ACCEPTED" {
			t.Fatalf("regular Go JSON did not accept the ambiguous status: %+v %v", decoded, err)
		}
		f.p.Receipts[i].PayloadB64 = base64.StdEncoding.EncodeToString([]byte(ambiguous))
		f.p.Receipts[i].SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(
			f.priv["acp"], append([]byte(SignatureDomain), []byte(ambiguous)...)))
		if err := Verify(f.p, f.e, f.pub, f.now); err == nil {
			t.Fatal("G01-G05 verifier accepted a correctly re-signed but ambiguous source status")
		}
		return
	}
	t.Fatal("missing run receipt")
}
