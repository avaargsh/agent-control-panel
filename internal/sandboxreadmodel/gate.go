// Package sandboxreadmodel evaluates local, non-authoritative Sandbox status
// projections. It never owns leases, Permit, commands, or provider operations.
package sandboxreadmodel

import (
	"errors"
	"unicode"
)

const CandidateSchema = "acp.sandbox-read-projection.candidate.v0"

type JournalState string

const (
	JournalPermitUnavailable JournalState = "PERMIT_UNAVAILABLE"
	JournalPrepared          JournalState = "PREPARED"
	JournalDispatching       JournalState = "DISPATCHING"
	JournalRunning           JournalState = "RUNNING"
	JournalUnknown           JournalState = "UNKNOWN"
	JournalExited            JournalState = "EXITED"
	JournalFailedConfirmed   JournalState = "FAILED_CONFIRMED"
)

type LeaseState string

const (
	LeaseClaimed   LeaseState = "CLAIMED"
	LeaseReleasing LeaseState = "RELEASING"
	LeaseReleased  LeaseState = "RELEASED"
)

type NextAction string

const (
	NextHold    NextAction = "HOLD"
	NextInspect NextAction = "INSPECT_ONLY"
	NextObserve NextAction = "OBSERVE_ONLY"
	NextVerify  NextAction = "VERIFY_ONLY"
)

var ErrUntrustedObservation = errors.New("ACP sandbox projection is untrusted, stale or out of scope")

type Expected struct {
	TenantID             string
	RunID                string
	RuntimeAttemptID     string
	SandboxUID           string
	CommandID            string
	ExecutorAttemptID    string
	MinJournalGeneration uint64
	MinLeaseGeneration   uint64
}

type Observation struct {
	SchemaVersion     string
	TenantID          string
	RunID             string
	RuntimeAttemptID  string
	SandboxUID        string
	CommandID         string
	ExecutorAttemptID string
	JournalGeneration uint64
	LeaseGeneration   uint64
	JournalState      JournalState
	LeaseState        LeaseState
}

type Assessment struct {
	Next               NextAction
	CanDispatch        bool
	CanRetry           bool
	CanDeclareSuccess  bool
	CanDeclareReleased bool
}

// validOpaqueRef guards only this ACP-local projection boundary. Actual service
// identifier formats and wire schema remain unratified and owned by Sandbox.
func validOpaqueRef(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func validStatus(j JournalState, l LeaseState) bool {
	switch j {
	case JournalPermitUnavailable, JournalPrepared, JournalDispatching,
		JournalRunning, JournalUnknown, JournalExited, JournalFailedConfirmed:
	default:
		return false
	}
	switch l {
	case LeaseClaimed, LeaseReleasing, LeaseReleased:
		return true
	default:
		return false
	}
}

// Evaluate yields a read-only UI/reconciliation hint, NEVER an authenticated
// execution decision or release acknowledgement. Caller must separately
// authenticate the source; this package has no authority to verify Permit,
// sandbox process, provider UID absence or independent evidence.
//
// In particular, UNKNOWN or DISPATCHING MUST NOT imply a safe command retry;
// EXITED and RELEASED are observations, not finality/cleanup proof.
func Evaluate(expected Expected, observed Observation) (Assessment, error) {
	denied := Assessment{Next: NextHold}
	for _, ref := range []string{expected.TenantID, expected.RunID, expected.RuntimeAttemptID,
		expected.SandboxUID, expected.CommandID, expected.ExecutorAttemptID} {
		if !validOpaqueRef(ref) {
			return denied, ErrUntrustedObservation
		}
	}
	if expected.MinJournalGeneration == 0 || expected.MinLeaseGeneration == 0 ||
		observed.SchemaVersion != CandidateSchema ||
		observed.TenantID != expected.TenantID || observed.RunID != expected.RunID ||
		observed.RuntimeAttemptID != expected.RuntimeAttemptID ||
		observed.SandboxUID != expected.SandboxUID || observed.CommandID != expected.CommandID ||
		observed.ExecutorAttemptID != expected.ExecutorAttemptID ||
		observed.JournalGeneration < expected.MinJournalGeneration ||
		observed.LeaseGeneration < expected.MinLeaseGeneration ||
		!validStatus(observed.JournalState, observed.LeaseState) {
		return denied, ErrUntrustedObservation
	}
	if observed.LeaseState != LeaseClaimed {
		// Even a self-reported RELEASED needs independently verified absence
		// of the exact sandbox/provider UID, not a stale state snapshot.
		return Assessment{Next: NextInspect}, nil
	}
	switch observed.JournalState {
	case JournalPermitUnavailable, JournalPrepared:
		return Assessment{Next: NextHold}, nil
	case JournalDispatching, JournalUnknown:
		return Assessment{Next: NextInspect}, nil
	case JournalRunning:
		return Assessment{Next: NextObserve}, nil
	case JournalExited, JournalFailedConfirmed:
		return Assessment{Next: NextVerify}, nil
	default:
		return denied, ErrUntrustedObservation
	}
}
