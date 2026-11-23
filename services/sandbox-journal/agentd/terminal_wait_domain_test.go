package agentd

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// A signature only authenticates the signer and bytes. It must not turn an
// impossible Linux OS Wait result into a confirmed terminal source fact.
// Normal Linux exit status is 0..255; a signaled process has ExitCode=-1
// and a nonzero signal. Reject forged or buggy signer payloads even if
// cryptographically valid and bound to the original attempt.
func TestVerifyTerminalRejectsImpossibleLinuxWaitOutcomes(t *testing.T) {
	_, ref := startOwnedTestProcess(t, "10")
	public, private := testSourceInspectKey(t)

	cases := []struct {
		name   string
		status string
		code   int
		signal int
		accept bool
	}{
		{name: "clean_exit", status: Exited, code: 0, signal: 0, accept: true},
		{name: "confirmed_nonzero_exit", status: FailedConfirmed, code: 7, signal: 0, accept: true},
		{name: "highest_normal_linux_exit", status: FailedConfirmed, code: 255, signal: 0, accept: true},
		{name: "confirmed_sigkill", status: FailedConfirmed, code: -1, signal: 9, accept: true},
		{name: "negative_exit_without_signal", status: FailedConfirmed, code: -1, signal: 0},
		{name: "other_negative_exit_without_signal", status: FailedConfirmed, code: -2, signal: 0},
		{name: "out_of_range_normal_exit", status: FailedConfirmed, code: 256, signal: 0},
		{name: "oversized_normal_exit", status: FailedConfirmed, code: 1024, signal: 0},
		{name: "signaled_with_numeric_exit", status: FailedConfirmed, code: 7, signal: 9},
		{name: "failed_status_without_failure", status: FailedConfirmed, code: 0, signal: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			receipt := TerminalReceipt{
				Schema: TerminalSchema, Source: "agentd.os.wait",
				Ref: ref, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
				Status: tc.status, ExitCode: tc.code, Signal: tc.signal,
				JournalRevision: 2,
			}
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			signature := ed25519.Sign(private, append([]byte(TerminalDomain), raw...))
			got, err := verifyTerminal(raw, signature, digest(raw), ref, public)
			if tc.accept {
				if err != nil || got != receipt {
					t.Fatalf("valid signed original Linux Wait rejected: %+v, %v", got, err)
				}
			} else if !errors.Is(err, ErrUnverified) {
				t.Fatalf("impossible signed Linux Wait was accepted: %+v, %v", got, err)
			}
		})
	}
}
