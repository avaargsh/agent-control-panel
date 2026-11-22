package postfault

import "testing"

// Both Sandbox before/after snapshots can be signed by the same trusted
// owner yet describe an ambiguous filesystem root. Equality of noncanonical
// strings cannot establish that an authorized physical workspace was
// preserved across SIGKILL. These are contract tests, not provider I/O.
func TestPostfaultRejectsNoncanonicalSignedSandboxRoot(t *testing.T) {
	for _, root := range []struct {
		name string
		path string
	}{
		{"parent_escape", "/workspace/../other"},
		{"dot_segment", "/workspace/./agent"},
		{"duplicate_separator", "/workspace//agent"},
		{"root_only", "/"},
		{"control_byte", "/workspace/agent\nforged"},
	} {
		t.Run(root.name, func(t *testing.T) {
			b, keys, signers, now := fixtureRecoveryBundle(t)
			for _, phase := range []string{"before_fault", "after_recovery"} {
				mutateReport(t, &b, signers, "sandbox", phase, func(o *Observation) {
					o.Sandbox.RootPath = root.path
				})
			}
			if err := Verify(b, keys, now); err == nil {
				t.Fatalf("signed noncanonical workspace root %q was accepted", root.path)
			}
		})
	}
}

// An UNKNOWN command must not already carry a terminal exit receipt before
// the fault: that combination contradicts an unresolved lost-ACK state.
// A new post-fault journal revision + InspectCount must not conceal corrupt
// pre-fault source evidence even when both reports were signed.
func TestPostfaultRejectsPreFaultUnknownWithTerminalReceipt(t *testing.T) {
	b, keys, signers, now := fixtureRecoveryBundle(t)
	mutateReport(t, &b, signers, "agentd", "before_fault", func(o *Observation) {
		o.Command.ExitReceiptDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	})
	if err := Verify(b, keys, now); err == nil {
		t.Fatal("pre-fault UNKNOWN with preexisting terminal exit receipt was accepted")
	}
}
