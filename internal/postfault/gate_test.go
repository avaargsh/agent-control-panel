package postfault

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixtureRecoveryBundle(t *testing.T) (Bundle, map[string]ed25519.PublicKey, map[string]ed25519.PrivateKey, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	subject := Subject{
		TenantID: "tenant-a", RunID: "run-123", SessionID: "session-123",
		WorkflowID: "agent-run/v1/run-123", GuardOperationID: "guard-op-1",
	}
	faultAt := now.Add(-time.Minute)
	bundle := Bundle{
		Schema: BundleVersion, Subject: subject,
		Fault: Fault{ID: "sigkill-worker-1", Kind: "worker_sigkill", At: faultAt},
	}
	keys := make(map[string]ed25519.PublicKey)
	signers := make(map[string]ed25519.PrivateKey)
	for _, authority := range []string{"runtime", "sandbox", "agentd", "guard"} {
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[authority], signers[authority] = pub, private
		for _, phase := range []string{"before_fault", "after_recovery"} {
			report := Observation{
				Schema: ObservationVersion, Authority: authority, Phase: phase,
				Subject: subject, FaultID: bundle.Fault.ID, ObservedAt: faultAt.Add(-time.Second),
			}
			if phase == "after_recovery" {
				report.ObservedAt = faultAt.Add(time.Second)
			}
			switch authority {
			case "runtime":
				report.Runtime = &RuntimeObservation{
					Status: "RUNNING", HistoryDigest: "sha256:" + strings.Repeat("a", 64),
					CheckpointDigest: "sha256:" + strings.Repeat("b", 64),
					BreakerState:     "CLOSED", BreakerEpoch: 4, BreakerVersion: 7,
					Recovered: phase == "after_recovery",
				}
			case "sandbox":
				report.Sandbox = &SandboxObservation{
					LeaseID: "lease-1", SandboxUID: "sandbox-uid-1",
					WorkspaceID: "workspace-1", Generation: 3,
					RootPath: "/workspace/agent", SentinelPath: ".acp-continuity",
					SentinelDigest:   "sha256:" + strings.Repeat("c", 64),
					ReadbackVerified: true, ProviderState: "ACTIVE",
				}
			case "agentd":
				report.Command = &CommandObservation{
					CommandID: "command-1", AttemptID: "command-attempt-1", ProviderCommandUID: "process-uid-1",
					JournalVersion: 10, State: "UNKNOWN", DispatchCount: 1,
				}
				if phase == "after_recovery" {
					report.Command.JournalVersion = 11
					report.Command.State = "EXITED"
					report.Command.InspectCount = 1
					report.Command.Source = "agentd.inspect"
					report.Command.ExitReceiptDigest = "sha256:" + strings.Repeat("d", 64)
				}
			case "guard":
				report.Guard = &GuardObservation{
					PermitID: "permit-1", PermitEpoch: 8, Status: "VALID", PermitExpiresAt: now.Add(10 * time.Minute),
					ActionDigest: "sha256:" + strings.Repeat("e", 64),
					Revalidated:  phase == "after_recovery",
				}
			}
			bundle.Receipts = append(bundle.Receipts, signFixture(t, report, private))
		}
	}
	return bundle, keys, signers, now
}

func signFixture(t *testing.T, report Observation, signer ed25519.PrivateKey) Receipt {
	t.Helper()
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(signer, append([]byte(SignatureDomain), payload...))
	return Receipt{
		Authority: report.Authority, Phase: report.Phase,
		PayloadB64:   base64.StdEncoding.EncodeToString(payload),
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
	}
}

func mutateReport(t *testing.T, b *Bundle, signers map[string]ed25519.PrivateKey, authority, phase string, mutate func(*Observation)) {
	t.Helper()
	for i, receipt := range b.Receipts {
		if receipt.Authority != authority || receipt.Phase != phase {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(receipt.PayloadB64)
		if err != nil {
			t.Fatal(err)
		}
		var report Observation
		if err := json.Unmarshal(payload, &report); err != nil {
			t.Fatal(err)
		}
		mutate(&report)
		b.Receipts[i] = signFixture(t, report, signers[authority])
		return
	}
	t.Fatal("missing signed fixture report")
}

func TestPostfaultIndependentSignedAuthoritiesPassCompleteRecovery(t *testing.T) {
	bundle, keys, _, now := fixtureRecoveryBundle(t)
	if err := Verify(bundle, keys, now); err != nil {
		t.Fatalf("complete independently signed recovery failed: %v", err)
	}
}

func TestPostfaultMissingOrForgedAuthorityCannotPass(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*testing.T, *Bundle, map[string]ed25519.PublicKey, map[string]ed25519.PrivateKey)
	}{
		{"sandbox_missing", func(_ *testing.T, b *Bundle, _ map[string]ed25519.PublicKey, _ map[string]ed25519.PrivateKey) {
			out := b.Receipts[:0]
			for _, r := range b.Receipts {
				if r.Authority != "sandbox" {
					out = append(out, r)
				}
			}
			b.Receipts = out
		}},
		{"signature_tampered", func(_ *testing.T, b *Bundle, _ map[string]ed25519.PublicKey, _ map[string]ed25519.PrivateKey) {
			b.Receipts[0].SignatureB64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}},
		{"wrong_source_key", func(_ *testing.T, _ *Bundle, keys map[string]ed25519.PublicKey, _ map[string]ed25519.PrivateKey) {
			keys["sandbox"] = keys["runtime"]
		}},
		{"duplicate_signed_phase", func(_ *testing.T, b *Bundle, _ map[string]ed25519.PublicKey, _ map[string]ed25519.PrivateKey) {
			b.Receipts[1] = b.Receipts[0]
		}},
		{"cross_run_rebinding", func(t *testing.T, b *Bundle, _ map[string]ed25519.PublicKey, signers map[string]ed25519.PrivateKey) {
			mutateReport(t, b, signers, "sandbox", "after_recovery", func(o *Observation) { o.Subject.RunID = "different-run" })
		}},
		{"future_observation", func(t *testing.T, b *Bundle, _ map[string]ed25519.PublicKey, signers map[string]ed25519.PrivateKey) {
			mutateReport(t, b, signers, "guard", "after_recovery", func(o *Observation) { o.ObservedAt = o.ObservedAt.Add(10 * time.Minute) })
		}},
		{"forged_fault_id", func(t *testing.T, b *Bundle, _ map[string]ed25519.PublicKey, signers map[string]ed25519.PrivateKey) {
			mutateReport(t, b, signers, "guard", "after_recovery", func(o *Observation) { o.FaultID = "different-fault" })
		}},
		{"replayed_pre_fault_timestamp", func(t *testing.T, b *Bundle, _ map[string]ed25519.PublicKey, signers map[string]ed25519.PrivateKey) {
			mutateReport(t, b, signers, "guard", "after_recovery", func(o *Observation) { o.ObservedAt = b.Fault.At.Add(-time.Second) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, keys, signers, now := fixtureRecoveryBundle(t)
			tc.edit(t, &b, keys, signers)
			if err := Verify(b, keys, now); err == nil {
				t.Fatal("untrusted or incomplete proof passed")
			}
		})
	}
}

func TestPostfaultRejectsBrokenSandboxWorkspaceContinuity(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*SandboxObservation)
	}{
		{"changed_sandbox_uid", func(s *SandboxObservation) { s.SandboxUID = "replaced" }},
		{"changed_workspace_id", func(s *SandboxObservation) { s.WorkspaceID = "empty-worktree" }},
		{"changed_mount_root", func(s *SandboxObservation) { s.RootPath = "/tmp/new" }},
		{"changed_sentinel_bytes", func(s *SandboxObservation) { s.SentinelDigest = "sha256:" + strings.Repeat("f", 64) }},
		{"stale_lease_generation", func(s *SandboxObservation) { s.Generation-- }},
		{"readback_not_verified", func(s *SandboxObservation) { s.ReadbackVerified = false }},
		{"provider_missing", func(s *SandboxObservation) { s.ProviderState = "UNKNOWN" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, keys, signers, now := fixtureRecoveryBundle(t)
			mutateReport(t, &b, signers, "sandbox", "after_recovery", func(o *Observation) { tc.edit(o.Sandbox) })
			if err := Verify(b, keys, now); err == nil {
				t.Fatal("workspace continuity was falsely accepted")
			}
		})
	}
}

func TestPostfaultRejectsCommandUnknownWithoutAuthoritativeInspect(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*CommandObservation)
	}{
		{"still_unknown", func(c *CommandObservation) { c.State = "UNKNOWN" }},
		{"blind_replay", func(c *CommandObservation) { c.DispatchCount = 2 }},
		{"no_inspect", func(c *CommandObservation) { c.InspectCount = 0 }},
		{"no_new_journal_revision", func(c *CommandObservation) { c.JournalVersion = 10 }},
		{"wrong_command", func(c *CommandObservation) { c.CommandID = "new-command" }},
		{"replaced_process_uid", func(c *CommandObservation) { c.ProviderCommandUID = "other-process" }},
		{"no_external_receipt", func(c *CommandObservation) { c.ExitReceiptDigest = "" }},
		{"self_asserted_exit", func(c *CommandObservation) { c.Source = "worker.report" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, keys, signers, now := fixtureRecoveryBundle(t)
			mutateReport(t, &b, signers, "agentd", "after_recovery", func(o *Observation) { tc.edit(o.Command) })
			if err := Verify(b, keys, now); err == nil {
				t.Fatal("UNKNOWN command incorrectly reconciled or retried")
			}
		})
	}
}

func TestPostfaultRequiresFreshGuardPermitAndUnchangedRuntimeBreakerEpoch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		authority string
		edit      func(*Observation)
	}{
		{"permit_revoked", "guard", func(o *Observation) { o.Guard.Status = "REVOKED" }},
		{"permit_epoch_changed", "guard", func(o *Observation) { o.Guard.PermitEpoch++ }},
		{"permit_expired", "guard", func(o *Observation) { o.Guard.PermitExpiresAt = o.ObservedAt.Add(time.Second) }},
		{"permit_expiry_extended_silently", "guard", func(o *Observation) { o.Guard.PermitExpiresAt = o.Guard.PermitExpiresAt.Add(time.Hour) }},
		{"permit_changed", "guard", func(o *Observation) { o.Guard.PermitID = "replacement" }},
		{"guard_not_revalidated", "guard", func(o *Observation) { o.Guard.Revalidated = false }},
		{"breaker_open", "runtime", func(o *Observation) { o.Runtime.BreakerState = "OPEN" }},
		{"breaker_epoch_changed", "runtime", func(o *Observation) { o.Runtime.BreakerEpoch++ }},
		{"workflow_not_recovered", "runtime", func(o *Observation) { o.Runtime.Recovered = false }},
		{"checkpoint_lost", "runtime", func(o *Observation) { o.Runtime.CheckpointDigest = "sha256:" + strings.Repeat("f", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, keys, signers, now := fixtureRecoveryBundle(t)
			mutateReport(t, &b, signers, tc.authority, "after_recovery", tc.edit)
			if err := Verify(b, keys, now); err == nil {
				t.Fatal("stale or unauthorized resumed execution accepted")
			}
		})
	}
}
