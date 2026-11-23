package postfault

import "testing"

// A post-fault observation claiming an inspect count of N is not a fresh
// InspectCommand if the pre-fault journal already recorded N inspections.
// The after-recovery journal revision and a signed "agentd.inspect" source
// label alone do not establish a new inspection across the worker SIGKILL.
func TestPostfaultRejectsReplayedCommandInspectCount(t *testing.T) {
	bundle, keys, signers, now := fixtureRecoveryBundle(t)
	mutateReport(t, &bundle, signers, "agentd", "before_fault", func(o *Observation) {
		o.Command.InspectCount = 1
	})
	// The fixture's after-recovery count is also 1. Its journal revision
	// advances from 10 to 11 and its terminal state is otherwise valid,
	// so an implementation checking only InspectCount > 0 will incorrectly
	// accept the stale inspection as recovery evidence.
	if err := Verify(bundle, keys, now); err == nil {
		t.Fatal("post-fault recovery accepted reused pre-fault InspectCount without a new AgentD inspection")
	}
}

// Do not prohibit legitimate prior inspections: a durable UNKNOWN can
// already have been inspected unsuccessfully before the fault. After
// recovery requires strictly more inspections, not an absolute count of 1.
func TestPostfaultAcceptsFreshCommandInspectCountAfterPriorInspect(t *testing.T) {
	bundle, keys, signers, now := fixtureRecoveryBundle(t)
	mutateReport(t, &bundle, signers, "agentd", "before_fault", func(o *Observation) {
		o.Command.InspectCount = 2
	})
	mutateReport(t, &bundle, signers, "agentd", "after_recovery", func(o *Observation) {
		o.Command.InspectCount = 3
	})
	if err := Verify(bundle, keys, now); err != nil {
		t.Fatalf("monotonically increasing post-fault AgentD inspection count was rejected: %v", err)
	}
}
