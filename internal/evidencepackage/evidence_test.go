package evidencepackage

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/postfault"
)

type fixture struct {
	p    Package
	e    Expected
	pub  map[string]ed25519.PublicKey
	priv map[string]ed25519.PrivateKey
	now  time.Time
}

func hash(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }

func signStatement(t *testing.T, s Statement, private ed25519.PrivateKey) Receipt {
	t.Helper()
	original := []byte("fixture-native:" + s.Authority + ":" + s.Stage)
	s.OriginalDigest = DigestRaw(original)
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return Receipt{
		Stage: s.Stage, Authority: s.Authority,
		PayloadB64:   base64.StdEncoding.EncodeToString(raw),
		OriginalB64:  base64.StdEncoding.EncodeToString(original),
		SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(SignatureDomain), raw...))),
	}
}

func fixturePackage(t *testing.T) fixture {
	t.Helper()
	now := time.Date(2026, 11, 22, 11, 0, 0, 0, time.UTC)
	fault := postfault.Fault{ID: "fault-1", Kind: "worker_sigkill", At: now.Add(-2 * time.Minute)}
	subject := postfault.Subject{
		TenantID: "tenant-1", RunID: "run-1", SessionID: "session-1",
		WorkflowID: "agent-run/v1/run-1", GuardOperationID: "op-1",
	}
	e := Expected{
		Schema: ExpectedSchema, Subject: subject, Fault: fault,
		RunIntentID: "intent-1", RequestDigest: hash("a"),
		AllocationID: "allocation-1", ProviderUID: "provider-1", ProviderGeneration: 7,
	}
	f := fixture{
		e: e, now: now,
		p: Package{
			Schema: Schema, Subject: subject, RunIntentID: e.RunIntentID,
			RequestDigest: e.RequestDigest, Fault: fault,
		},
		pub: make(map[string]ed25519.PublicKey), priv: make(map[string]ed25519.PrivateKey),
	}
	for _, role := range []string{"acp", "decision", "runtime", "guard", "sandbox", "agentd", "compute"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.pub[role], f.priv[role] = pub, priv
	}
	proof := postfault.Bundle{Schema: postfault.BundleVersion, Subject: subject, Fault: fault}
	for _, authority := range []string{"runtime", "sandbox", "agentd", "guard"} {
		for _, phase := range []string{"before_fault", "after_recovery"} {
			o := postfault.Observation{
				Schema: postfault.ObservationVersion, Authority: authority, Phase: phase,
				FaultID: fault.ID, Subject: subject, ObservedAt: fault.At.Add(-time.Second),
			}
			if phase == "after_recovery" {
				o.ObservedAt = fault.At.Add(time.Second)
			}
			switch authority {
			case "runtime":
				o.Runtime = &postfault.RuntimeObservation{
					Status: "RUNNING", HistoryDigest: hash("b"), CheckpointDigest: hash("c"),
					BreakerState: "CLOSED", BreakerEpoch: 5, BreakerVersion: 7,
					Recovered: phase == "after_recovery",
				}
			case "sandbox":
				o.Sandbox = &postfault.SandboxObservation{
					LeaseID: "lease-1", SandboxUID: "sandbox-1", WorkspaceID: "work-1", Generation: 2,
					RootPath: "/workspace/agent", SentinelPath: "sentinel",
					SentinelDigest: hash("d"), ReadbackVerified: true, ProviderState: "ACTIVE",
				}
			case "agentd":
				o.Command = &postfault.CommandObservation{
					CommandID: "cmd-1", AttemptID: "attempt-1", ProviderCommandUID: "proc-1",
					State: "UNKNOWN", JournalVersion: 9, DispatchCount: 1,
				}
				if phase == "after_recovery" {
					o.Command.State = "EXITED"
					o.Command.JournalVersion = 10
					o.Command.InspectCount = 1
					o.Command.Source = "agentd.inspect"
					o.Command.ExitReceiptDigest = hash("e")
				}
			case "guard":
				o.Guard = &postfault.GuardObservation{
					PermitID: "permit-1", PermitEpoch: 3,
					PermitExpiresAt: now.Add(10 * time.Minute), Status: "VALID",
					ActionDigest: hash("f"), Revalidated: phase == "after_recovery",
				}
			}
			raw, err := json.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			proof.Receipts = append(proof.Receipts, postfault.Receipt{
				Authority: authority, Phase: phase,
				PayloadB64: base64.StdEncoding.EncodeToString(raw),
				SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(
					f.priv[authority], append([]byte(postfault.SignatureDomain), raw...))),
			})
		}
	}
	proofRaw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	f.p.PostfaultB64 = base64.StdEncoding.EncodeToString(proofRaw)
	for _, stage := range stages {
		s := Statement{
			Schema: ObservationSchema, Stage: stage.stage, Authority: stage.authority,
			Subject: subject, RunIntentID: e.RunIntentID, RequestDigest: e.RequestDigest,
			ObservedAt: fault.At.Add(-10 * time.Second),
		}
		switch stage.stage {
		case "run":
			s.Status = "ACCEPTED"
		case "decision":
			s.Status = "ACCEPTED"
			s.DecisionID = "decision-1"
			s.DecisionDigest = hash("1")
		case "permit":
			s.Status = "VALID"
			s.DecisionID = "decision-1"
			s.DecisionDigest = hash("1")
			s.PermitID = "permit-1"
			s.PermitEpoch = 3
			s.ActionDigest = hash("f")
		case "recovery":
			s.Status = "RECOVERED"
			s.ObservedAt = fault.At.Add(3 * time.Second)
			s.CommandID = "cmd-1"
			s.CheckpointDigest = hash("c")
			s.BreakerEpoch = 5
			s.PermitID = "permit-1"
			s.PermitEpoch = 3
			s.ActionDigest = hash("f")
		case "guard_release":
			s.Status = "SETTLED"
			s.ObservedAt = fault.At.Add(4 * time.Second)
			s.PermitID = "permit-1"
			s.PermitEpoch = 3
			s.ActionDigest = hash("f")
		case "sandbox_release":
			s.Status = "RELEASED"
			s.ObservedAt = fault.At.Add(5 * time.Second)
			s.SandboxUID = "sandbox-1"
			s.ProviderAbsent = true
		case "compute_release":
			s.Status = "RELEASED"
			s.ObservedAt = fault.At.Add(6 * time.Second)
			s.AllocationID = e.AllocationID
			s.ProviderUID = e.ProviderUID
			s.ProviderGeneration = e.ProviderGeneration
			s.ProviderAbsent = true
		}
		f.p.Receipts = append(f.p.Receipts, signStatement(t, s, f.priv[stage.authority]))
	}
	return f
}

func mutate(t *testing.T, f *fixture, stage string, edit func(*Statement)) {
	t.Helper()
	for i, r := range f.p.Receipts {
		if r.Stage != stage {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(r.PayloadB64)
		if err != nil {
			t.Fatal(err)
		}
		var s Statement
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		edit(&s)
		f.p.Receipts[i] = signStatement(t, s, f.priv[r.Authority])
		return
	}
	t.Fatal("missing fixture stage")
}

func TestEvidencePackageValidatesSameRunSignedLifecycle(t *testing.T) {
	f := fixturePackage(t)
	if err := Verify(f.p, f.e, f.pub, f.now); err != nil {
		t.Fatalf("expected signed lifecycle to verify: %v", err)
	}
}

func TestEvidencePackageRejectsSemanticDriftDespiteValidServiceSignatures(t *testing.T) {
	cases := []struct {
		name, stage string
		edit        func(*Statement)
	}{
		{"wrong_tenant", "decision", func(s *Statement) { s.Subject.TenantID = "tenant-b" }},
		{"changed_run", "run", func(s *Statement) { s.Subject.RunID = "run-b" }},
		{"decision_binding", "permit", func(s *Statement) { s.DecisionID = "wrong-decision" }},
		{"reused_action", "recovery", func(s *Statement) { s.ActionDigest = hash("2") }},
		{"stale_permit_epoch", "recovery", func(s *Statement) { s.PermitEpoch = 2 }},
		{"changed_breaker_epoch", "recovery", func(s *Statement) { s.BreakerEpoch = 6 }},
		{"lost_checkpoint", "recovery", func(s *Statement) { s.CheckpointDigest = hash("3") }},
		{"different_command", "recovery", func(s *Statement) { s.CommandID = "cmd-2" }},
		{"unsettled_guard", "guard_release", func(s *Statement) { s.Status = "UNKNOWN" }},
		{"sandbox_not_absent", "sandbox_release", func(s *Statement) { s.ProviderAbsent = false }},
		{"swapped_sandbox", "sandbox_release", func(s *Statement) { s.SandboxUID = "sandbox-2" }},
		{"provider_not_absent", "compute_release", func(s *Statement) { s.ProviderAbsent = false }},
		{"provider_uid_changed", "compute_release", func(s *Statement) { s.ProviderUID = "provider-2" }},
		{"generation_changed", "compute_release", func(s *Statement) { s.ProviderGeneration = 6 }},
		{"pre_fault_release", "compute_release", func(s *Statement) { s.ObservedAt = s.ObservedAt.Add(-time.Hour) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fixturePackage(t)
			mutate(t, &f, tc.stage, tc.edit)
			if err := Verify(f.p, f.e, f.pub, f.now); err == nil {
				t.Fatal("cross-service inconsistency passed")
			}
		})
	}
}

func TestEvidencePackageRejectsMissingForgedOrUntrustedReceipts(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*fixture)
	}{
		{"tampered_original_bytes", func(f *fixture) {
			f.p.Receipts[0].OriginalB64 = base64.StdEncoding.EncodeToString([]byte("changed native receipt"))
		}},
		{"missing_original_bytes", func(f *fixture) { f.p.Receipts[0].OriginalB64 = "" }},
		{"missing_release", func(f *fixture) { f.p.Receipts = f.p.Receipts[:len(f.p.Receipts)-1] }},
		{"duplicate_stage", func(f *fixture) { f.p.Receipts[0] = f.p.Receipts[1] }},
		{"forged_signature", func(f *fixture) {
			f.p.Receipts[0].SignatureB64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}},
		{"shared_signing_key", func(f *fixture) { f.pub["compute"] = f.pub["guard"] }},
		{"untrusted_expected", func(f *fixture) { f.e.ProviderUID = "provider-substitution" }},
		{"no_postfault", func(f *fixture) { f.p.PostfaultB64 = "" }},
		{"tampered_postfault", func(f *fixture) { f.p.PostfaultB64 = base64.StdEncoding.EncodeToString([]byte("{}")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixturePackage(t)
			tc.edit(&f)
			if err := Verify(f.p, f.e, f.pub, f.now); err == nil {
				t.Fatal("untrusted package accepted")
			}
		})
	}
}
