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
	"unicode"
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
	TenantID         string `json:"tenant_id"`
	RunID            string `json:"run_id"`
	SessionID        string `json:"session_id"`
	WorkflowID       string `json:"workflow_id"`
	GuardOperationID string `json:"guard_operation_id"`
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
	CommandID          string `json:"command_id"`
	AttemptID          string `json:"attempt_id"`
	ProviderCommandUID string `json:"provider_command_uid"`
	JournalVersion     uint64 `json:"journal_version"`
	State              string `json:"state"`
	DispatchCount      uint64 `json:"dispatch_count"`
	InspectCount       uint64 `json:"inspect_count"`
	Source             string `json:"source"`
	ExitReceiptDigest  string `json:"exit_receipt_digest"`
	Replayed           bool   `json:"replayed"`
}

type GuardObservation struct {
	PermitID        string    `json:"permit_id"`
	PermitEpoch     uint64    `json:"permit_epoch"`
	PermitExpiresAt time.Time `json:"permit_expires_at"`
	Status          string    `json:"status"`
	ActionDigest    string    `json:"action_digest"`
	Revalidated     bool      `json:"revalidated"`
}

type Observation struct {
	Schema     string              `json:"schema"`
	Authority  string              `json:"authority"`
	Phase      string              `json:"phase"`
	ObservedAt time.Time           `json:"observed_at"`
	FaultID    string              `json:"fault_id"`
	Subject    Subject             `json:"subject"`
	Runtime    *RuntimeObservation `json:"runtime,omitempty"`
	Sandbox    *SandboxObservation `json:"sandbox,omitempty"`
	Command    *CommandObservation `json:"command,omitempty"`
	Guard      *GuardObservation   `json:"guard,omitempty"`
}

func safeID(s string) bool {
	if s == "" || len(s) > 256 || strings.TrimSpace(s) != s {
		return false
	}
	for _, ch := range s {
		if ch <= 32 || ch >= 127 || ch == '\\' || ch == '?' || ch == '#' {
			return false
		}
	}
	return true
}

func validSubject(s Subject) bool {
	return safeID(s.TenantID) && safeID(s.RunID) &&
		safeID(s.SessionID) && safeID(s.WorkflowID) && safeID(s.GuardOperationID)
}

func validDigest(s string) bool {
	if len(s) != len("sha256:")+64 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, c := range strings.TrimPrefix(s, "sha256:") {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// decodeStrict rejects ambiguous JSON, including duplicate keys encoded
// with different Unicode escapes. DisallowUnknownFields alone does not
// reject duplicates: encoding/json silently accepts the last field value.
// Check the entire token tree before interpreting any signed observation.
// StrictDecode is shared by the standalone postfault CLI and the signed
// observation validator, so outer bundle/independent expected bindings use
// the same duplicate-key rejection as nested signed receipts.
func StrictDecode(data []byte, dst any) bool {
	return decodeStrict(data, dst)
}

// foldedJSONKey canonicalizes Unicode SimpleFold equivalence classes so
// different JSON member spellings that encoding/json could match to the same
// struct field cannot overwrite one another in signed evidence. This is
// linear in input size, unlike comparing every key with every previous key.
func foldedJSONKey(key string) string {
	var normalized strings.Builder
	normalized.Grow(len(key))
	for _, r := range key {
		least := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < least {
				least = next
			}
		}
		normalized.WriteRune(least)
	}
	return normalized.String()
}

func decodeStrict(data []byte, dst any) bool {
	tokens := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := tokens.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for tokens.More() {
				rawKey, err := tokens.Token()
				if err != nil {
					return err
				}
				key, ok := rawKey.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				folded := foldedJSONKey(key)
				if seen[folded] {
					return errors.New("duplicate or case-folded JSON key")
				}
				seen[folded] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := tokens.Token()
			return err
		case '[':
			for tokens.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := tokens.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if walk() != nil || tokens.Decode(new(any)) != io.EOF {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(dst) != nil {
		return false
	}
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
		if p {
			count++
		}
	}
	if count != 1 {
		return false
	}
	switch o.Authority {
	case "runtime":
		return o.Runtime != nil
	case "sandbox":
		return o.Sandbox != nil
	case "agentd":
		return o.Command != nil
	case "guard":
		return o.Guard != nil
	default:
		return false
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
			o.Subject != b.Subject || o.FaultID != b.Fault.ID || !validateSingleOwner(o) {
			return failure("untrusted or cross-run authority statement")
		}
		if o.ObservedAt.IsZero() || o.ObservedAt.After(now) {
			return failure("future or missing authority observation time")
		}
		if phase == "before_fault" {
			if !o.ObservedAt.Before(b.Fault.At) {
				return failure("missing pre-fault evidence")
			}
		} else if !o.ObservedAt.After(b.Fault.At) || now.Sub(o.ObservedAt) > maxPostFaultAge {
			return failure("stale or pre-fault recovery observation")
		}
		observed[key] = o
	}
	for _, authority := range []string{"runtime", "sandbox", "agentd", "guard"} {
		if _, ok := observed[authority+"/before_fault"]; !ok {
			return failure("missing pre-fault authority")
		}
		if _, ok := observed[authority+"/after_recovery"]; !ok {
			return failure("missing post-fault authority")
		}
	}
	return checkContinuity(observed, b.Fault.At, now)
}

func checkContinuity(observed map[string]Observation, faultAt, now time.Time) error {
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
		!safeID(sb.SentinelPath) || strings.HasPrefix(sb.SentinelPath, "/") || strings.Contains(sb.SentinelPath, "..") ||
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
	if !safeID(cb.CommandID) || !safeID(cb.AttemptID) || !safeID(cb.ProviderCommandUID) ||
		cb.State != "UNKNOWN" || cb.DispatchCount != 1 || cb.JournalVersion == 0 ||
		cb.Replayed || ca.Replayed || ca.CommandID != cb.CommandID ||
		ca.AttemptID != cb.AttemptID || ca.ProviderCommandUID != cb.ProviderCommandUID ||
		ca.DispatchCount != 1 ||
		// A pre-fault inspection can already have been recorded while the
		// command remained UNKNOWN. Replaying that positive count after a
		// Worker SIGKILL is NOT evidence of a fresh InspectCommand, even
		// if a different journal event advanced the journal revision.
		ca.JournalVersion <= cb.JournalVersion ||
		ca.InspectCount <= cb.InspectCount ||
		ca.Source != "agentd.inspect" || !validDigest(ca.ExitReceiptDigest) ||
		(ca.State != "EXITED" && ca.State != "FAILED_CONFIRMED") {
		return failure("external command UNKNOWN not authoritatively reconciled")
	}
	gb := observed["guard/before_fault"].Guard
	ga := observed["guard/after_recovery"].Guard
	if !safeID(gb.PermitID) || gb.PermitEpoch == 0 ||
		gb.PermitExpiresAt.IsZero() || !gb.PermitExpiresAt.After(faultAt) ||
		!ga.PermitExpiresAt.Equal(gb.PermitExpiresAt) ||
		!ga.PermitExpiresAt.After(now) ||
		!validDigest(gb.ActionDigest) ||
		gb.Status != "VALID" || ga.Status != "VALID" ||
		!ga.Revalidated || ga.PermitID != gb.PermitID ||
		ga.PermitEpoch != gb.PermitEpoch ||
		ga.ActionDigest != gb.ActionDigest {
		return failure("Guard Permit revoked, stale or not freshly revalidated")
	}
	return nil
}
