package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/postfault"
)

func headAcceptanceTestBinding() expectedBinding {
	return expectedBinding{
		Schema: expectedBindingVersion,
		Subject: postfault.Subject{
			TenantID: "tenant-a", RunID: "run-a", SessionID: "session-a",
			WorkflowID: "agent-run/v1/run-a", GuardOperationID: "guard-operation-a",
		},
		FaultID: "fault-a", FaultAt: time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC),
		AgentDRef: &postfault.AgentDWaitRef{
			TenantID: "tenant-a", RunID: "run-a", RuntimeAttemptID: "runtime-attempt-a",
			SandboxUID: "sandbox-a", CommandID: "command-a", AttemptID: "command-attempt-a",
			ProviderCommandUID: "provider-a",
			RequestDigest:      "sha256:" + strings.Repeat("a", 64),
			GuardPermitID:      "permit-a", PermitEpoch: 8,
			ProcessPID: 1111, ProcessStartTicks: 2222,
			HostBootID: "11111111-1111-1111-1111-111111111111",
		},
		AgentDGuardOperationID: "guard-operation-a",
		AgentDHead: &agentDHeadBinding{
			InspectCount: 3, JournalVersion: 3, Digest: "sha256:" + strings.Repeat("b", 64),
		},
	}
}

func signAcceptedHead(t *testing.T, statement headAcceptanceStatement, private ed25519.PrivateKey) []byte {
	t.Helper()
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope := headAcceptanceEnvelope{
		PayloadB64: base64.StdEncoding.EncodeToString(payload),
		SignatureB64: base64.StdEncoding.EncodeToString(
			ed25519.Sign(private, append([]byte(headAcceptanceDomain), payload...))),
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestHeadAcceptanceRequiresIndependentSignerAndExactOriginalRunPermitHead(t *testing.T) {
	acceptorPublic, acceptorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourcePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	expected := headAcceptanceTestBinding()
	otherKeys := map[string]ed25519.PublicKey{"agentd": sourcePublic}
	base := headAcceptanceStatement{
		Schema:  headAcceptanceSchema,
		Binding: expected, Revision: 7,
		AcceptedAt: now.Add(-30 * time.Minute),
		ExpiresAt:  now.Add(30 * time.Minute),
	}
	if err := verifyHeadAcceptance(signAcceptedHead(t, base, acceptorPrivate),
		expected, acceptorPublic, otherKeys, now); err != nil {
		t.Fatalf("distinct exact signed Run/Guard/Attempt/Head was rejected: %v", err)
	}
	cases := []struct {
		name   string
		change func(*headAcceptanceStatement)
	}{
		{"foreign_run", func(a *headAcceptanceStatement) { a.Binding.Subject.RunID = "run-other" }},
		{"foreign_tenant", func(a *headAcceptanceStatement) { a.Binding.Subject.TenantID = "tenant-other" }},
		{"foreign_fault", func(a *headAcceptanceStatement) { a.Binding.FaultID = "fault-other" }},
		{"foreign_guard_operation", func(a *headAcceptanceStatement) { a.Binding.AgentDGuardOperationID = "guard-other" }},
		{"foreign_permit_id", func(a *headAcceptanceStatement) { a.Binding.AgentDRef.GuardPermitID = "permit-other" }},
		{"stale_permit_epoch", func(a *headAcceptanceStatement) { a.Binding.AgentDRef.PermitEpoch-- }},
		{"foreign_command", func(a *headAcceptanceStatement) { a.Binding.AgentDRef.CommandID = "command-other" }},
		{"different_head_digest", func(a *headAcceptanceStatement) { a.Binding.AgentDHead.Digest = "sha256:" + strings.Repeat("c", 64) }},
		{"head_rollback", func(a *headAcceptanceStatement) {
			a.Binding.AgentDHead.InspectCount--
			a.Binding.AgentDHead.JournalVersion--
		}},
		{"not_yet_accepted", func(a *headAcceptanceStatement) { a.AcceptedAt = now.Add(time.Second) }},
		{"expired", func(a *headAcceptanceStatement) { a.ExpiresAt = now }},
		{"overlong_validity", func(a *headAcceptanceStatement) { a.ExpiresAt = a.AcceptedAt.Add(25 * time.Hour) }},
		{"accepted_before_fault", func(a *headAcceptanceStatement) { a.AcceptedAt = expected.FaultAt.Add(-time.Second) }},
		{"zero_revision", func(a *headAcceptanceStatement) { a.Revision = 0 }},
		{"wrong_schema", func(a *headAcceptanceStatement) { a.Schema = "untrusted/v1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			statement := base
			// Marshal/unmarshal deep copies nested Ref/Head pointers.
			raw, err := json.Marshal(base)
			if err != nil || json.Unmarshal(raw, &statement) != nil {
				t.Fatal("invalid fixture")
			}
			tc.change(&statement)
			if err := verifyHeadAcceptance(signAcceptedHead(t, statement, acceptorPrivate),
				expected, acceptorPublic, otherKeys, now); err == nil {
				t.Fatal("accepted signed Head with different original Run/Guard/Attempt/Head or unsafe time")
			}
		})
	}
	if err := verifyHeadAcceptance(signAcceptedHead(t, base, acceptorPrivate),
		expected, sourcePublic, otherKeys, now); err == nil {
		t.Fatal("source AgentD public key was accepted as independent Head signer")
	}
	if err := verifyHeadAcceptance(signAcceptedHead(t, base, acceptorPrivate),
		expected, acceptorPublic, map[string]ed25519.PublicKey{"agentd": acceptorPublic}, now); err == nil {
		t.Fatal("AgentD evidence-signing key reused as Head acceptance authority")
	}
}

func TestHeadAcceptanceRejectsUnsignedNoncanonicalAndAlteredEnvelope(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	binding := headAcceptanceTestBinding()
	st := headAcceptanceStatement{
		Schema: headAcceptanceSchema, Binding: binding, Revision: 1,
		AcceptedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	good := signAcceptedHead(t, st, private)
	cases := map[string][]byte{
		"no_signature":           bytes.Replace(good, []byte(`"signature_b64":"`), []byte(`"signature_b64":"bad`), 1),
		"extra_envelope_key":     bytes.Replace(good, []byte(`{"payload_b64":`), []byte(`{"untrusted":1,"payload_b64":`), 1),
		"duplicate_envelope_key": append(bytes.TrimSuffix(good, []byte("}")), []byte(`,"payload_b64":"malicious"}`)...),
		"trailing_data":          append(bytes.Clone(good), []byte("{}")...),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if err := verifyHeadAcceptance(raw, binding, public,
				map[string]ed25519.PublicKey{"agentd": source}, now); err == nil {
				t.Fatal("accepted malformed or unauthenticated Head acceptance")
			}
		})
	}
	// The source cannot re-sign a payload as an independent acceptance record,
	// even if the source knows the complete Head and all Run/Permit identifiers.
	_, sourceSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyHeadAcceptance(signAcceptedHead(t, st, sourceSigner),
		binding, public, map[string]ed25519.PublicKey{"agentd": source}, now); err == nil {
		t.Fatal("AgentD source-issued Head was accepted using independent verifier key")
	}
}
