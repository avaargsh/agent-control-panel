package sandboxreadmodel

import (
	"errors"
	"testing"
)

// This deterministic evaluation is limited to ACP's local read projection.
// It is not an AgentD execution, sandbox isolation or independent source test.
func TestSecurityEvaluationProjectionMatrix(t *testing.T) {
	expected := Expected{
		TenantID: "evaluation-tenant", RunID: "evaluation-run",
		RuntimeAttemptID: "runtime-attempt", SandboxUID: "sandbox-fixture",
		CommandID: "command-fixture", ExecutorAttemptID: "executor-attempt",
		MinJournalGeneration: 4, MinLeaseGeneration: 2,
	}
	base := Observation{
		SchemaVersion: CandidateSchema, TenantID: expected.TenantID, RunID: expected.RunID,
		RuntimeAttemptID: expected.RuntimeAttemptID, SandboxUID: expected.SandboxUID,
		CommandID: expected.CommandID, ExecutorAttemptID: expected.ExecutorAttemptID,
		JournalGeneration: 4, LeaseGeneration: 2,
	}
	states := []struct {
		journal JournalState
		claimed NextAction
	}{
		{JournalPermitUnavailable, NextHold},
		{JournalPrepared, NextHold},
		{JournalDispatching, NextInspect},
		{JournalRunning, NextObserve},
		{JournalUnknown, NextInspect},
		{JournalExited, NextVerify},
		{JournalFailedConfirmed, NextVerify},
	}
	for _, state := range states {
		for _, lease := range []LeaseState{LeaseClaimed, LeaseReleasing, LeaseReleased} {
			t.Run(string(state.journal)+"/"+string(lease), func(t *testing.T) {
				observation := base
				observation.JournalState = state.journal
				observation.LeaseState = lease
				want := Assessment{Next: NextInspect}
				if lease == LeaseClaimed {
					want.Next = state.claimed
				}
				if got, err := Evaluate(expected, observation); err != nil || got != want {
					t.Fatalf("projection must remain advisory: got %+v, err %v; want %+v", got, err, want)
				}
				// Missing binding or outdated observations must return HOLD,
				// including when a valid status reports terminality or release.
				for _, invalid := range []struct {
					name   string
					change func(*Observation)
				}{
					{"missing-run", func(o *Observation) { o.RunID = "" }},
					{"stale-journal", func(o *Observation) { o.JournalGeneration = 3 }},
					{"stale-lease", func(o *Observation) { o.LeaseGeneration = 1 }},
				} {
					t.Run(invalid.name, func(t *testing.T) {
						candidate := observation
						invalid.change(&candidate)
						got, err := Evaluate(expected, candidate)
						if !errors.Is(err, ErrUntrustedObservation) || got != (Assessment{Next: NextHold}) {
							t.Fatalf("untrusted projection must hold: got %+v, err %v", got, err)
						}
					})
				}
			})
		}
	}
}
