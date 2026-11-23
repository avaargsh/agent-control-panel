package sandboxreadmodel

import (
	"errors"
	"testing"
)

func fixture() (Expected, Observation) {
	expected := Expected{
		TenantID: "tenant-1", RunID: "11111111-1111-4111-8111-111111111111",
		RuntimeAttemptID: "attempt-1", SandboxUID: "sandbox-uid-1", CommandID: "command-1",
		ExecutorAttemptID: "executor-attempt-1", MinJournalGeneration: 4, MinLeaseGeneration: 2,
	}
	o := Observation{
		SchemaVersion: CandidateSchema, TenantID: expected.TenantID, RunID: expected.RunID,
		RuntimeAttemptID: expected.RuntimeAttemptID, SandboxUID: expected.SandboxUID,
		CommandID: expected.CommandID, ExecutorAttemptID: expected.ExecutorAttemptID,
		JournalGeneration: 4, LeaseGeneration: 2, JournalState: JournalPermitUnavailable,
		LeaseState: LeaseClaimed,
	}
	return expected, o
}

func TestNonDispatchCandidateNeverGrantsEffectRetryOrFinality(t *testing.T) {
	states := []struct {
		state  JournalState
		action NextAction
	}{
		{JournalPermitUnavailable, NextHold},
		{JournalPrepared, NextHold},
		{JournalDispatching, NextInspect},
		{JournalRunning, NextObserve},
		{JournalUnknown, NextInspect},
		{JournalExited, NextVerify},
		{JournalFailedConfirmed, NextVerify},
	}
	for _, tc := range states {
		t.Run(string(tc.state), func(t *testing.T) {
			e, o := fixture()
			o.JournalState = tc.state
			got, err := Evaluate(e, o)
			if err != nil {
				t.Fatal(err)
			}
			if got.Next != tc.action || got.CanDispatch || got.CanRetry || got.CanDeclareReleased || got.CanDeclareSuccess {
				t.Fatalf("non-authoritative observation was promoted: %+v", got)
			}
		})
	}
}

func TestUnknownAndLostACKRequireInspectionNotBlindRetry(t *testing.T) {
	for _, state := range []JournalState{JournalDispatching, JournalUnknown} {
		e, o := fixture()
		o.JournalState = state
		got, err := Evaluate(e, o)
		if err != nil || got.Next != NextInspect || got.CanRetry {
			t.Fatalf("lost ACK outcome promoted to safe retry: %+v %v", got, err)
		}
	}
}

func TestReportedReleaseIsNotProofOfProviderUIDAbsence(t *testing.T) {
	for _, state := range []JournalState{JournalPermitUnavailable, JournalUnknown, JournalExited, JournalFailedConfirmed} {
		e, o := fixture()
		o.JournalState = state
		o.LeaseState = LeaseReleased
		got, err := Evaluate(e, o)
		if err != nil || got.Next != NextInspect || got.CanDeclareReleased || got.CanDeclareSuccess {
			t.Fatalf("claimed release was promoted to verified absence: %+v %v", got, err)
		}
	}
}

func TestStaleGenerationCrossTenantAndWrongAttemptFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Expected, *Observation)
	}{
		{"tenant", func(_ *Expected, o *Observation) { o.TenantID = "other" }},
		{"Run", func(_ *Expected, o *Observation) { o.RunID = "22222222-2222-4222-8222-222222222222" }},
		{"runtime attempt", func(_ *Expected, o *Observation) { o.RuntimeAttemptID = "attempt-2" }},
		{"sandbox UID", func(_ *Expected, o *Observation) { o.SandboxUID = "other-sandbox" }},
		{"command", func(_ *Expected, o *Observation) { o.CommandID = "other-command" }},
		{"executor attempt", func(_ *Expected, o *Observation) { o.ExecutorAttemptID = "other-executor-attempt" }},
		{"stale command generation", func(_ *Expected, o *Observation) { o.JournalGeneration = 3 }},
		{"stale lease generation", func(_ *Expected, o *Observation) { o.LeaseGeneration = 1 }},
		{"zero required generation", func(e *Expected, _ *Observation) { e.MinJournalGeneration = 0 }},
		{"empty bound identity", func(e *Expected, _ *Observation) { e.CommandID = "" }},
		{"unknown journal status", func(_ *Expected, o *Observation) { o.JournalState = "SUCCEEDED" }},
		{"unknown lease status", func(_ *Expected, o *Observation) { o.LeaseState = "FREE" }},
		{"unknown version", func(_ *Expected, o *Observation) { o.SchemaVersion = "other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, o := fixture()
			tc.change(&e, &o)
			if got, err := Evaluate(e, o); !errors.Is(err, ErrUntrustedObservation) || got.Next != NextHold {
				t.Fatalf("untrusted or stale observation was accepted: %+v %v", got, err)
			}
		})
	}
}

func TestNonReleasedLeaseRequiresInspectionBeforeFinalizing(t *testing.T) {
	for _, lease := range []LeaseState{LeaseClaimed, LeaseReleasing, LeaseReleased} {
		e, o := fixture()
		o.JournalState = JournalExited
		o.LeaseState = lease
		got, err := Evaluate(e, o)
		if err != nil || got.CanDeclareReleased || got.CanDeclareSuccess {
			t.Fatalf("exit status did not require external verification: %+v %v", got, err)
		}
		if lease != LeaseClaimed && got.Next != NextInspect {
			t.Fatalf("lease still needs exact UID absence inspection: %+v", got)
		}
	}
}
