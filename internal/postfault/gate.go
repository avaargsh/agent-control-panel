// Package postfault verifies independently signed, cross-authority recovery
// observations. It cannot create observations or substitute itself for the
// authoritative Runtime, Sandbox, AgentD or Guard services.
package postfault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	BundleVersion      = "acp.postfault-bundle/v1"
	ObservationVersion = "acp.postfault-observation/v1"
	SignatureDomain    = "acp.postfault-observation/v1\x00"
	maxObservationSize = 8192
	maxPostFaultAge    = 5 * time.Minute
	maxFaultAge        = 30 * time.Minute
)

var ErrUnverifiedRecovery = errors.New("postfault recovery proof unavailable or invalid")

// Subject is the original authoritative Run binding, not a model-generated ID.
// Attempt IDs are intentionally not frozen here: Temporal may replace workers.
type Subject struct {
	TenantID          string `json:"tenant_id"`
	RunID             string `json:"run_id"`
	SessionID         string `json:"session_id"`
	WorkflowID        string `json:"workflow_id"`
	GuardOperationID  string `json:"guard_operation_id"`
}

type Fault struct {
	ID   string    `json:"id"`
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
}

// Every receipt carries exact source bytes signed by a separately trusted key.
// The signing authority is provisioned externally; test-generated signatures
// only validate this parser, NEVER a real sandbox/provider recovery.
type Receipt struct {
	Authority    string `json:"authority"`
	Phase        string `json:"phase"`
	PayloadB64   string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
}

type Bundle struct {
	Schema   string    `json:"schema"`
	Subject  Subject   `json:"subject"`
	Fault    Fault     `json:"fault"`
	Receipts []Receipt `json:"receipts"`
}

type RuntimeObservation struct {
	Status           string `json:"status"`
	HistoryDigest    string `json:"history_digest"`
	CheckpointDigest string `json:"checkpoint_digest"`
	BreakerState     string `json:"breaker_state"`
	BreakerEpoch     uint64 `json:"breaker_epoch"`
	BreakerVersion   uint64 `json:"breaker_version"`
	Recovered        bool   `json:"recovered"`
}

type SandboxObservation struct {
	LeaseID          string `json:"lease_id"`
	SandboxUID       string `json:"sandbox_uid"`
	WorkspaceID      string `json:"workspace_id"`
	Generation       uint64 `json:"generation"`
	RootPath         string `json:"root_path"`
	SentinelPath     string `json:"sentinel_path"`
	SentinelDigest   string `json:"sentinel_digest"`
	ReadbackVerified bool   `json:"readback_verified"`
	ProviderState    string `json:"provider_state"`
}

type CommandObservation struct {
	CommandID         string `json:"command_id"`
	AttemptID         string `json:"attempt_id"`
	JournalVersion    uint64 `json:"journal_version"`
	State             string `json:"state"`
	DispatchCount     uint64 `json:"dispatch_count"`
	InspectCount      uint64 `json:"inspect_count"`
	Source            string `json:"source"`
	ExitReceiptDigest string `json:"exit_receipt_digest"`
	Replayed          bool   `json:"replayed"`
}

type GuardObservation struct {
	PermitID    string `json:"permit_id"`
	PermitEpoch uint64 `json:"permit_epoch"`
	Status      string `json:"status"`
	ActionDigest string `json:"action_digest"`
	Revalidated bool   `json:"revalidated"`
}

type Observation struct {
	Schema     string               `json:"schema"`
	Authority  string               `json:"authority"`
	Phase      string               `json:"phase"`
	ObservedAt time.Time            `json:"observed_at"`
	Subject    Subject              `json:"subject"`
	Runtime    *RuntimeObservation  `json:"runtime,omitempty"`
	Sandbox    *SandboxObservation  `json:"sandbox,omitempty"`
	Command    *CommandObservation  `json:"command,omitempty"`
	Guard      *GuardObservation    `json:"guard,omitempty"`
}

func safeID(s string) bool {
	if s == "" || len(s) > 256 || strings.TrimSpace(s) != s { return false }
	for _, ch := range s {
		if ch <= 32 || ch >= 127 || ch == '\\' || ch == '?' || ch == '#' { return false }
	}
	return true
}

func validSubject(s Subject) bool {
	return safeID(s.TenantID) && safeID(s.RunID) &&
		safeID(s.SessionID) && safeID(s.WorkflowID) && safeID(s.GuardOperationID)
}

func validDigest(s string) bool {
	if len(s) != len("sha256:")+64 || !strings.HasPrefix(s, "sha256:") { return false }
	for _, c := range strings.TrimPrefix(s, "sha256:") {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) { return false }
	}
	return true
}

func decodeStrict(data []byte, dst any) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(dst) != nil { return false }
	return decoder.Decode(new(any)) == io.EOF
}

func allowedAuthority(authority string) bool {
	switch authority {
	case "runtime", "sandbox", "agentd", "guard":
		return true
	default:
		return false
	}
}

func validateSingleOwner(o Observation) bool {
	count := 0
	for _, p := range []bool{o.Runtime != nil, o.Sandbox != nil, o.Command != nil, o.Guard != nil} {
		if p { count++ }
	}
	if count != 1 { return false }
	switch o.Authority {
	case "runtime": return o.Runtime != nil
	case "sandbox": return o.Sandbox != nil
	case "agentd": return o.Command != nil
	case "guard": return o.Guard != nil
	default: return false
	}
}

func failure(reason string) error {
	// Do not embed arbitrary source payloads, provider errors or credentials.
	return fmt.Errorf("%w: %s", ErrUnverifiedRecovery, reason)
}

// Verify requires eight signed observations: two *independent* source-signed
// snapshots per authority (before fault and fresh after recovery). The keys
// must come from trusted out-of-band service identities, never the bundle.
func Verify(b Bundle, keys map[string]ed25519.PublicKey, now time.Time) error {
	if b.Schema != BundleVersion || !validSubject(b.Subject) ||
		!safeID(b.Fault.ID) || b.Fault.Kind != "worker_sigkill" ||
		b.Fault.At.IsZero() || b.Fault.At.After(now) || now.Sub(b.Fault.At) > maxFaultAge {
		return failure("invalid fault or original Run binding")
	}
	if len(b.Receipts) != 8 || len(keys) != 4 {
		return failure("missing required authority phase")
	}
	for authority, key := range keys {
		if !allowedAuthority(authority) || len(key) != ed25519.PublicKeySize {
			return failure("invalid trusted authority key")
		}
		for other, otherKey := range keys {
			if authority != other && bytes.Equal(key, otherKey) {
				return failure("authorities share one signing key")
			}
		}
	}
	observed := make(map[string]Observation, 8)
	for _, receipt := range b.Receipts {
		authority := receipt.Authority
		phase := receipt.Phase
		if !allowedAuthority(authority) || (phase != "before_fault" && phase != "after_recovery") {
			return failure("invalid authority phase")
		}
		key := authority + "/" + phase
		if _, exists := observed[key]; exists {
			return failure("duplicate authority phase")
		}
		data, err := base64.StdEncoding.Strict().DecodeString(receipt.PayloadB64)
		if err != nil || len(data) == 0 || len(data) > maxObservationSize {
			return failure("invalid bounded authority payload")
		}
		signature, err := base64.StdEncoding.Strict().DecodeString(receipt.SignatureB64)
		if err != nil || len(signature) != ed25519.SignatureSize ||
			!ed25519.Verify(keys[authority], append([]byte(SignatureDomain), data...), signature) {
			return failure("authority signature verification failed")
		}
		var o Observation
		if !decodeStrict(data, &o) || o.Schema != ObservationVersion ||
			o.Authority != authority || o.Phase != phase ||
			o.Subject != b.Subject || !validateSingleOwner(o) {
			return failure("untrusted or cross-run authority statement")
		}
		if o.ObservedAt.IsZero() || o.ObservedAt.After(now) {
			return failure("future or missing authority observation time")
		}
		if phase == "before_fault" {
			if !o.ObservedAt.Before(b.Fault.At) { return failure("missing pre-fault evidence") }
		} else if !o.ObservedAt.After(b.Fault.At) || now.Sub(o.ObservedAt) > maxPostFaultAge {
			return failure("stale or pre-fault recovery observation")
		}
		observed[key] = o
	}
	for _, authority := range []string{"runtime", "sandbox", "agentd", "guard"} {
		if _, ok := observed[authority+"/before_fault"]; !ok { return failure("missing pre-fault authority") }
		if _, ok := observed[authority+"/after_recovery"]; !ok { return failure("missing post-fault authority") }
	}
	return checkContinuity(observed)
}

func checkContinuity(observed map[string]Observation) error {
	rb := observed["runtime/before_fault"].Runtime
	ra := observed["runtime/after_recovery"].Runtime
	if rb.Status != "RUNNING" || ra.Status != "RUNNING" || !ra.Recovered ||
		!validDigest(rb.HistoryDigest) || !validDigest(ra.HistoryDigest) ||
		!validDigest(rb.CheckpointDigest) || ra.CheckpointDigest != rb.CheckpointDigest ||
		rb.BreakerState != "CLOSED" || ra.BreakerState != "CLOSED" ||
		rb.BreakerEpoch == 0 || ra.BreakerEpoch != rb.BreakerEpoch ||
		rb.BreakerVersion == 0 || ra.BreakerVersion < rb.BreakerVersion {
		return failure("Runtime recovery, checkpoint or breaker epoch not continuous")
	}
	sb := observed["sandbox/before_fault"].Sandbox
	sa := observed["sandbox/after_recovery"].Sandbox
	if !safeID(sb.LeaseID) || !safeID(sb.SandboxUID) || !safeID(sb.WorkspaceID) ||
		sb.Generation == 0 || !strings.HasPrefix(sb.RootPath, "/") ||
		!safeID(sb.SentinelPath) || strings.Contains(sb.SentinelPath, "..") ||
		!validDigest(sb.SentinelDigest) ||
		sb.ProviderState != "ACTIVE" || sa.ProviderState != "ACTIVE" ||
		!sb.ReadbackVerified || !sa.ReadbackVerified ||
		sb.LeaseID != sa.LeaseID || sb.SandboxUID != sa.SandboxUID ||
		sb.WorkspaceID != sa.WorkspaceID || sb.Generation != sa.Generation ||
		sb.RootPath != sa.RootPath || sb.SentinelPath != sa.SentinelPath ||
		sb.SentinelDigest != sa.SentinelDigest {
		return failure("Sandbox lease, directory or byte readback not continuous")
	}
	cb := observed["agentd/before_fault"].Command
	ca := observed["agentd/after_recovery"].Command
	if !safeID(cb.CommandID) || !safeID(cb.AttemptID) ||
		cb.State != "UNKNOWN" || cb.DispatchCount != 1 || cb.JournalVersion == 0 ||
		cb.Replayed || ca.Replayed || ca.CommandID != cb.CommandID ||
		ca.AttemptID != cb.AttemptID || ca.DispatchCount != 1 ||
		ca.JournalVersion <= cb.JournalVersion || ca.InspectCount == 0 ||
		ca.Source != "agentd.inspect" || !validDigest(ca.ExitReceiptDigest) ||
		(ca.State != "EXITED" && ca.State != "FAILED_CONFIRMED") {
		return failure("external command UNKNOWN not authoritatively reconciled")
	}
	gb := observed["guard/before_fault"].Guard
	ga := observed["guard/after_recovery"].Guard
	if !safeID(gb.PermitID) || gb.PermitEpoch == 0 ||
		!validDigest(gb.ActionDigest) ||
		gb.Status != "VALID" || ga.Status != "VALID" ||
		!ga.Revalidated || ga.PermitID != gb.PermitID ||
		ga.PermitEpoch != gb.PermitEpoch ||
		ga.ActionDigest != gb.ActionDigest {
		return failure("Guard Permit revoked, stale or not freshly revalidated")
	}
	return nil
}
