package issuegoal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
	"strings"
	"testing"
)

func TestDecodePreparedAcceptsExactPreparedInput(t *testing.T) {
	p, err := Prepare([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, input, raw, err := DecodePrepared(wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != p || input.Kind != InputKind || input.IssueURL != "https://github.com/example/repository/issues/123" {
		t.Fatal("invalid round trip")
	}
	if err := runintent.VerifyExecutionInput(runintent.Intent{TenantID: p.Target.TenantID, ProjectID: p.Target.ProjectID, AgentID: p.Target.AgentID, ReleaseID: p.Target.ReleaseID, SessionID: p.Target.SessionID, IdempotencyKey: p.IdempotencyKey, RequestDigest: p.RequestDigest}, raw); err != nil {
		t.Fatal(err)
	}
}

func TestDecodePreparedRejectsModifiedOrAmbiguousProposal(t *testing.T) {
	p, err := Prepare([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := json.Marshal(p)
	tampered := p
	tampered.RequestDigest = "sha256:" + strings.Repeat("a", 64)
	badScope := p
	badScope.Target.TenantID = "tenant-b"
	badBase64 := p
	badBase64.ExecutionInputBase64 = "**bad**"
	tooLarge := p
	tooLarge.ExecutionInputBase64 = strings.Repeat("A", 50000)
	badKind := p
	raw, _ := base64.StdEncoding.DecodeString(p.ExecutionInputBase64)
	wrong := bytes.Replace(raw, []byte(`"kind":"github.issue.fix.v1"`), []byte(`"kind":"other"`), 1)
	badKind.ExecutionInputBase64 = base64.StdEncoding.EncodeToString(wrong)
	badKind.RequestDigest, _ = runintent.ExecutionInputDigest(runintent.Intent{TenantID: p.Target.TenantID, ProjectID: p.Target.ProjectID, AgentID: p.Target.AgentID, ReleaseID: p.Target.ReleaseID, SessionID: p.Target.SessionID, IdempotencyKey: p.IdempotencyKey}, wrong)
	nonCanonical := p
	raw = append([]byte(" "), raw...)
	nonCanonical.ExecutionInputBase64 = base64.StdEncoding.EncodeToString(raw)
	nonCanonical.RequestDigest, _ = runintent.ExecutionInputDigest(runintent.Intent{TenantID: p.Target.TenantID, ProjectID: p.Target.ProjectID, AgentID: p.Target.AgentID, ReleaseID: p.Target.ReleaseID, SessionID: p.Target.SessionID, IdempotencyKey: p.IdempotencyKey}, raw)
	cases := map[string][]byte{
		"digest changed":                          mustJSON(t, tampered),
		"tenant changed":                          mustJSON(t, badScope),
		"invalid base64":                          mustJSON(t, badBase64),
		"oversize base64":                         mustJSON(t, tooLarge),
		"kind rewritten with matching digest":     mustJSON(t, badKind),
		"non canonical input and matching digest": mustJSON(t, nonCanonical),
		"unknown top field":                       bytes.Replace(base, []byte(`"schema":`), []byte(`"extra":1,"schema":`), 1),
		"casefold duplicate top field":            bytes.Replace(base, []byte(`"schema":`), []byte(`"Schema":"ignored","schema":`), 1),
		"duplicate top field":                     bytes.Replace(base, []byte(`"schema":`), []byte(`"schema":"wrong","schema":`), 1),
		"missing target":                          bytes.Replace(base, []byte(`"tenant_id":"tenant-a"`), []byte(`"tenant_id":""`), 1),
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := DecodePrepared(wire); err == nil {
				t.Fatalf("accepted modified proposal: %s", wire)
			}
		})
	}
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
