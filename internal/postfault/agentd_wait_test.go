package postfault

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func waitSourceFixture(t *testing.T) (Bundle, map[string]ed25519.PublicKey,
	map[string]ed25519.PrivateKey, ExpectedAgentDWait, AgentDWaitStatement, time.Time) {
	t.Helper()
	b, keys, signers, now := fixtureRecoveryBundle(t)
	statement := AgentDWaitStatement{
		Schema: AgentDWaitSchema, Source: "agentd.os.wait",
		ObservedAt: b.Fault.At.Add(500 * time.Millisecond).Format(time.RFC3339Nano),
		Status: "EXITED", ExitCode: 0, Signal: 0, JournalRevision: 2,
		Ref: AgentDWaitRef{
			TenantID: b.Subject.TenantID, RunID: b.Subject.RunID,
			RuntimeAttemptID: "runtime-attempt-1", SandboxUID: "sandbox-uid-1",
			CommandID: "command-1", AttemptID: "command-attempt-1",
			ProviderCommandUID: "process-uid-1",
			RequestDigest: "sha256:" + strings.Repeat("a", 64),
			GuardPermitID: "permit-1", PermitEpoch: 8,
			ProcessPID: 12345, ProcessStartTicks: 123456,
			HostBootID: "11111111-2222-4333-8444-555555555555",
		},
	}
	expected := ExpectedAgentDWait{Ref: statement.Ref, GuardOperationID: b.Subject.GuardOperationID}
	return b, keys, signers, expected, statement, now
}

func signedWaitBytes(t *testing.T, statement AgentDWaitStatement,
	signer ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	return raw, ed25519.Sign(signer, append([]byte(AgentDWaitDomain), raw...))
}

func bindG05ExitDigest(t *testing.T, b *Bundle, signers map[string]ed25519.PrivateKey, raw []byte) {
	t.Helper()
	sum := sha256.Sum256(raw)
	mutateReport(t, b, signers, "agentd", "after_recovery", func(o *Observation) {
		o.Command.ExitReceiptDigest = fmt.Sprintf("sha256:%x", sum)
	})
}

func TestG05AcceptsOriginalSourceSignedWaitOnlyWithSameRunReceipt(t *testing.T) {
	b, keys, signers, expected, source, now := waitSourceFixture(t)
	raw, sig := signedWaitBytes(t, source, signers["agentd"])
	bindG05ExitDigest(t, &b, signers, raw)
	if err := VerifyWithAgentDWait(b, keys, expected, raw, sig, keys["agentd"], now); err != nil {
		t.Fatalf("matching real-source-format Wait evidence rejected: %v", err)
	}
}

// Every malformed source case preserves a valid postfault bundle. Several
// mutations are re-signed by the ACTUAL AgentD fixture key, so rejecting
// only invalid cryptographic signatures is insufficient to pass this suite.
func TestG05RejectsForeignSourceSignedWaitAndForgedJournalLink(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*AgentDWaitStatement, *ExpectedAgentDWait, *Bundle)
	}{
		{"foreign_run", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Ref.RunID = "other-run" }},
		{"foreign_tenant", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Ref.TenantID = "other-tenant" }},
		{"foreign_runtime_attempt", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Ref.RuntimeAttemptID = "other-attempt" }},
		{"foreign_command", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Ref.CommandID = "other-command" }},
		{"foreign_executor_attempt", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Ref.AttemptID = "other-executor-attempt" }},
		{"foreign_provider", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Ref.ProviderCommandUID = "other-process" }},
		{"other_sandbox", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Ref.SandboxUID = "other-sandbox" }},
		{"other_permit", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Ref.GuardPermitID = "other-permit" }},
		{"stale_permit_epoch", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Ref.PermitEpoch-- }},
		{"other_process_start", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Ref.ProcessStartTicks++ }},
		{"wrong_request_digest", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Ref.RequestDigest = "sha256:"+strings.Repeat("b",64) }},
		{"unbound_guard_operation", func(_ *AgentDWaitStatement, e *ExpectedAgentDWait, _ *Bundle) { e.GuardOperationID = "other-guard-op" }},
		{"invalid_terminal_source", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Source = "worker.report" }},
		{"not_an_os_terminal", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.Status = "UNKNOWN" }},
		{"inconsistent_exit_code", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, _ *Bundle) { s.ExitCode = 7 }},
		{"pre_fault_wait", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, b *Bundle) { s.ObservedAt = b.Fault.At.Add(-time.Second).Format(time.RFC3339Nano) }},
		{"future_wait", func(s *AgentDWaitStatement, _ *ExpectedAgentDWait, b *Bundle) { s.ObservedAt = b.Fault.At.Add(time.Hour).Format(time.RFC3339Nano) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, keys, signers, expected, source, now := waitSourceFixture(t)
			tc.edit(&source, &expected, &b)
			raw, sig := signedWaitBytes(t, source, signers["agentd"])
			bindG05ExitDigest(t, &b, signers, raw)
			if err := Verify(b, keys, now); err != nil {
				t.Fatalf("precondition: source-signed postfault bundle invalid: %v", err)
			}
			if err := VerifyWithAgentDWait(b, keys, expected, raw, sig, keys["agentd"], now); err == nil {
				t.Fatal("G05 accepted source Wait without original Run/Guard/command binding")
			}
		})
	}
}

func TestG05RejectsMissingTamperedOrMismatchedTerminalDigest(t *testing.T) {
	b, keys, signers, expected, source, now := waitSourceFixture(t)
	raw, sig := signedWaitBytes(t, source, signers["agentd"])
	for _, tc := range []struct {
		name string
		raw []byte
		sig []byte
		pub ed25519.PublicKey
		bind bool
	}{
		{"missing", nil, nil, keys["agentd"], true},
		{"unbound_digest", raw, sig, keys["agentd"], false},
		{"bad_signature", raw, make([]byte, ed25519.SignatureSize), keys["agentd"], true},
		{"wrong_owner_key", raw, sig, keys["guard"], true},
		{"altered_payload", append(append([]byte(nil),raw...), ' '), sig, keys["agentd"], true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyBundle := b
			copyBundle.Receipts = append([]Receipt(nil), b.Receipts...)
			if tc.bind {
				bindG05ExitDigest(t, &copyBundle, signers, raw)
			}
			if err := Verify(copyBundle, keys, now); err != nil {
				t.Fatalf("precondition: G05 bundle invalid: %v", err)
			}
			if err := VerifyWithAgentDWait(copyBundle, keys, expected, tc.raw, tc.sig, tc.pub, now); err == nil {
				t.Fatal("G05 accepted missing/tampered or unauthenticated original Wait")
			}
		})
	}
}
