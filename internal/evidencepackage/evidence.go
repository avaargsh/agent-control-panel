// Package evidencepackage performs read-only, offline consistency checks on
// independently signed receipt bytes. It never mints a Run, Permit or release.
package evidencepackage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/postfault"
)

const (
	Schema            = "acp.evidence-package/v2"
	ObservationSchema = "acp.evidence-observation/v2"
	ExpectedSchema    = "acp.evidence-expected/v2"
	SignatureDomain   = "acp.evidence-observation/v2\x00"
	maxReceiptBytes   = 16 << 10
	maxRecoveryBytes  = 128 << 10
)

var ErrUnverified = errors.New("cross-service evidence is incomplete or invalid")

// Expected must be obtained independently from authenticated ACP/Runtime,
// the fault injector and the actual provider allocation inspector. Never
// construct it from the package submitted for validation.
type Expected struct {
	Schema             string            `json:"schema"`
	Subject            postfault.Subject `json:"subject"`
	RunIntentID        string            `json:"run_intent_id"`
	RequestDigest      string            `json:"request_digest"`
	Fault              postfault.Fault   `json:"fault"`
	AllocationID       string            `json:"allocation_id"`
	ProviderUID        string            `json:"provider_uid"`
	ProviderGeneration uint64            `json:"provider_generation"`
	// SourceRevisions is an independently captured, authoritative head for
	// each stage. A signature without this head does not prevent stale replay.
	SourceRevisions map[string]uint64 `json:"source_revisions"`
}

type Receipt struct {
	Stage        string `json:"stage"`
	Authority    string `json:"authority"`
	PayloadB64   string `json:"payload_b64"`
	OriginalB64  string `json:"original_b64"`
	SignatureB64 string `json:"signature_b64"`
}

// Package contains the ORIGINAL signed receipt bytes, not reconstructed
// summaries. The postfault bundle contributes the four before/after recovery
// authorities; this envelope adds the cross-service lifecycle receipts.
type Package struct {
	Schema        string            `json:"schema"`
	Subject       postfault.Subject `json:"subject"`
	RunIntentID   string            `json:"run_intent_id"`
	RequestDigest string            `json:"request_digest"`
	Fault         postfault.Fault   `json:"fault"`
	PostfaultB64  string            `json:"postfault_b64"`
	Receipts      []Receipt         `json:"receipts"`
}

// Statement is a versioned source-signed EXPORT view, not a replacement for
// a service's own authoritative command/decision/permit/provider record.
type Statement struct {
	Schema             string            `json:"schema"`
	Authority          string            `json:"authority"`
	Stage              string            `json:"stage"`
	Subject            postfault.Subject `json:"subject"`
	RunIntentID        string            `json:"run_intent_id"`
	RequestDigest      string            `json:"request_digest"`
	OriginalDigest     string            `json:"original_digest"`
	SourceRevision     uint64            `json:"source_revision"`
	ObservedAt         time.Time         `json:"observed_at"`
	Status             string            `json:"status"`
	DecisionID         string            `json:"decision_id,omitempty"`
	DecisionDigest     string            `json:"decision_digest,omitempty"`
	ActionDigest       string            `json:"action_digest,omitempty"`
	PermitID           string            `json:"permit_id,omitempty"`
	PermitEpoch        uint64            `json:"permit_epoch,omitempty"`
	BreakerEpoch       uint64            `json:"breaker_epoch,omitempty"`
	CommandID          string            `json:"command_id,omitempty"`
	CheckpointDigest   string            `json:"checkpoint_digest,omitempty"`
	SandboxUID         string            `json:"sandbox_uid,omitempty"`
	AllocationID       string            `json:"allocation_id,omitempty"`
	ProviderUID        string            `json:"provider_uid,omitempty"`
	ProviderGeneration uint64            `json:"provider_generation,omitempty"`
	ProviderAbsent     bool              `json:"provider_absent,omitempty"`
}

var stages = []struct{ stage, authority string }{
	{"run", "acp"},
	{"decision", "decision"},
	{"permit", "guard"},
	{"recovery", "runtime"},
	{"guard_release", "guard"},
	{"sandbox_release", "sandbox"},
	{"compute_release", "compute"},
}

func reject(reason string) error {
	return fmt.Errorf("%w: %s", ErrUnverified, reason)
}

func identifier(s string) bool {
	if s == "" || len(s) > 256 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 33 || r > 126 || r == '\\' || r == '#' || r == '?' {
			return false
		}
	}
	return true
}
func digest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, r := range s[7:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// StrictDecode uses the same case-folded, duplicate-key rejecting parser
// as postfault. Having a separate lifecycle parser silently allowed a
// differently cased, re-signed status alias to override an original status.
// The source signature authenticates bytes, NOT their unambiguous decoding.
func StrictDecode(data []byte, target any) bool {
	return postfault.StrictDecode(data, target)
}

func expectedValid(e Expected) bool {
	if len(e.SourceRevisions) != len(stages) {
		return false
	}
	for _, stage := range stages {
		if e.SourceRevisions[stage.stage] == 0 {
			return false
		}
	}
	return e.Schema == ExpectedSchema &&
		identifier(e.Subject.TenantID) && identifier(e.Subject.RunID) &&
		identifier(e.Subject.SessionID) && identifier(e.Subject.WorkflowID) &&
		identifier(e.Subject.GuardOperationID) &&
		identifier(e.RunIntentID) && digest(e.RequestDigest) &&
		e.Fault.Kind == "worker_sigkill" && identifier(e.Fault.ID) &&
		!e.Fault.At.IsZero() && identifier(e.AllocationID) &&
		identifier(e.ProviderUID) && e.ProviderGeneration > 0
}
func keysValid(keys map[string]ed25519.PublicKey) bool {
	if len(keys) != 7 {
		return false
	}
	names := []string{"acp", "decision", "guard", "runtime", "sandbox", "agentd", "compute"}
	for i, name := range names {
		key, ok := keys[name]
		if !ok || len(key) != ed25519.PublicKeySize {
			return false
		}
		for _, prior := range names[:i] {
			if bytes.Equal(keys[prior], key) {
				return false
			}
		}
	}
	return true
}

// Verify requires all seven lifecycle receipts plus the separately signed
// eight-observation postfault bundle. It is only a CONSISTENCY verdict;
// service identity, actual I/O and physical absence require owner evidence.
func Verify(p Package, e Expected, keys map[string]ed25519.PublicKey, now time.Time) error {
	if !expectedValid(e) || p.Schema != Schema || p.Subject != e.Subject ||
		p.RunIntentID != e.RunIntentID || p.RequestDigest != e.RequestDigest ||
		p.Fault.ID != e.Fault.ID || p.Fault.Kind != e.Fault.Kind ||
		!p.Fault.At.Equal(e.Fault.At) || !keysValid(keys) {
		return reject("invalid independent binding or trust anchors")
	}
	rawRecovery, err := base64.StdEncoding.Strict().DecodeString(p.PostfaultB64)
	if err != nil || len(rawRecovery) == 0 || len(rawRecovery) > maxRecoveryBytes {
		return reject("missing bounded postfault evidence")
	}
	var recovery postfault.Bundle
	if !StrictDecode(rawRecovery, &recovery) || recovery.Subject != e.Subject ||
		recovery.Fault.ID != e.Fault.ID || !recovery.Fault.At.Equal(e.Fault.At) ||
		recovery.Fault.Kind != e.Fault.Kind {
		return reject("postfault bundle not bound to expected Run/fault")
	}
	recoveryKeys := map[string]ed25519.PublicKey{
		"runtime": keys["runtime"], "sandbox": keys["sandbox"],
		"agentd": keys["agentd"], "guard": keys["guard"],
	}
	if err := postfault.Verify(recovery, recoveryKeys, now); err != nil {
		return reject("postfault authority or recovery gate incomplete")
	}
	postfaultAfter := make(map[string]postfault.Observation)
	for _, r := range recovery.Receipts {
		raw, err := base64.StdEncoding.Strict().DecodeString(r.PayloadB64)
		if err != nil {
			return reject("invalid postfault observation bytes")
		}
		var o postfault.Observation
		if !StrictDecode(raw, &o) {
			return reject("invalid postfault observation")
		}
		if r.Phase == "after_recovery" {
			postfaultAfter[r.Authority] = o
		}
	}

	if len(p.Receipts) != len(stages) {
		return reject("missing stage or duplicate receipt")
	}
	statements := make(map[string]Statement, len(stages))
	for _, r := range p.Receipts {
		var owner string
		for _, want := range stages {
			if want.stage == r.Stage {
				owner = want.authority
				break
			}
		}
		if owner == "" || r.Authority != owner {
			return reject("wrong receipt owner or stage")
		}
		if _, exists := statements[r.Stage]; exists {
			return reject("duplicate receipt stage")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(r.PayloadB64)
		if err != nil || len(raw) == 0 || len(raw) > maxReceiptBytes {
			return reject("invalid original receipt bytes")
		}
		sig, err := base64.StdEncoding.Strict().DecodeString(r.SignatureB64)
		if err != nil || len(sig) != ed25519.SignatureSize ||
			!ed25519.Verify(keys[owner], append([]byte(SignatureDomain), raw...), sig) {
			return reject("signed receipt does not match trusted owner")
		}
		var s Statement
		if !StrictDecode(raw, &s) || s.Schema != ObservationSchema ||
			s.Authority != owner || s.Stage != r.Stage ||
			s.Subject != e.Subject || s.RunIntentID != e.RunIntentID ||
			s.RequestDigest != e.RequestDigest ||
			s.ObservedAt.IsZero() || s.ObservedAt.After(now) {
			return reject("source receipt not bound to the original Run")
		}
		native, err := base64.StdEncoding.Strict().DecodeString(r.OriginalB64)
		if err != nil || len(native) == 0 || len(native) > maxReceiptBytes ||
			!digest(s.OriginalDigest) || DigestRaw(native) != s.OriginalDigest ||
			s.SourceRevision != e.SourceRevisions[r.Stage] {
			return reject("source-native original receipt bytes do not match signed digest")
		}
		if r.Stage == "run" || r.Stage == "decision" || r.Stage == "permit" {
			if !s.ObservedAt.Before(e.Fault.At) {
				return reject("invalid pre-fault observation")
			}
		} else if !s.ObservedAt.After(e.Fault.At) {
			return reject("invalid post-fault observation")
		}
		statements[r.Stage] = s
	}
	if len(statements) != len(stages) {
		return reject("incomplete lifecycle stages")
	}
	run, dec, permit := statements["run"], statements["decision"], statements["permit"]
	resumed := statements["recovery"]
	guardReleased, sandboxReleased, computeReleased := statements["guard_release"], statements["sandbox_release"], statements["compute_release"]
	if run.Status != "ACCEPTED" || dec.Status != "ACCEPTED" ||
		!identifier(dec.DecisionID) || !digest(dec.DecisionDigest) {
		return reject("G01/G02: missing accepted Run or authoritative Decision")
	}
	// Signed receipt validity alone cannot justify a downstream decision
	// that predates its required upstream accepted Run, or a Guard Permit
	// that predates the accepted Decision it references. Equal timestamps
	// are allowed; source-owned causal journals remain the stronger proof.
	if dec.ObservedAt.Before(run.ObservedAt) ||
		permit.ObservedAt.Before(dec.ObservedAt) {
		return reject("G01/G03: signed Run, Decision and Permit stages out of order")
	}
	if permit.Status != "VALID" || permit.DecisionID != dec.DecisionID ||
		permit.DecisionDigest != dec.DecisionDigest ||
		!identifier(permit.PermitID) || permit.PermitEpoch == 0 ||
		!digest(permit.ActionDigest) {
		return reject("G03: Permit not bound to accepted Decision")
	}
	postRuntime := postfaultAfter["runtime"].Runtime
	postCommand := postfaultAfter["agentd"].Command
	postGuard := postfaultAfter["guard"].Guard
	postSandbox := postfaultAfter["sandbox"].Sandbox
	if postRuntime == nil || postCommand == nil || postGuard == nil || postSandbox == nil {
		return reject("G05: missing independently signed recovery facets")
	}
	if resumed.Status != "RECOVERED" || !identifier(resumed.CommandID) ||
		resumed.CommandID != postCommand.CommandID ||
		resumed.CheckpointDigest != postRuntime.CheckpointDigest ||
		!digest(resumed.CheckpointDigest) ||
		resumed.BreakerEpoch == 0 || resumed.BreakerEpoch != postRuntime.BreakerEpoch ||
		resumed.PermitID != permit.PermitID || resumed.PermitID != postGuard.PermitID ||
		resumed.PermitEpoch != permit.PermitEpoch || resumed.PermitEpoch != postGuard.PermitEpoch ||
		resumed.ActionDigest != permit.ActionDigest || resumed.ActionDigest != postGuard.ActionDigest {
		return reject("G03/G05: resumed command, checkpoint or authorization drift")
	}
	if guardReleased.Status != "SETTLED" || guardReleased.PermitID != permit.PermitID ||
		guardReleased.PermitEpoch != permit.PermitEpoch || guardReleased.ActionDigest != permit.ActionDigest ||
		guardReleased.ObservedAt.Before(resumed.ObservedAt) {
		return reject("G03/G04: protected operation settlement not observed")
	}
	// Independently signed, fresh observations can still be captured AFTER
	// a purported settlement. Merely verifying all signatures and Run IDs
	// would let a package present later AgentD Inspect / Guard revalidation
	// as if they justified an earlier protected-operation settlement.
	// This is a necessary timestamp consistency fence, not proof of real
	// execution or a substitute for authenticated source clocks.
	for _, authority := range []string{"runtime", "sandbox", "agentd", "guard"} {
		observedAt := postfaultAfter[authority].ObservedAt
		// RECOVERED is a cross-service lifecycle claim carrying the
		// reconciled command and Guard Permit references. It cannot claim
		// completed recovery before the independent evidence it depends on
		// was observed, even if a later Guard settlement is correctly dated.
		if guardReleased.ObservedAt.Before(observedAt) {
			return reject("G03/G04: settlement predates signed postfault recovery proof")
		}
		if resumed.ObservedAt.Before(observedAt) {
			return reject("G05: recovered Run predates signed postfault source proof")
		}
	}
	if sandboxReleased.Status != "RELEASED" || !sandboxReleased.ProviderAbsent ||
		sandboxReleased.SandboxUID != postSandbox.SandboxUID ||
		sandboxReleased.ObservedAt.Before(guardReleased.ObservedAt) {
		return reject("G04: Sandbox UID absence not independently observed")
	}
	if computeReleased.Status != "RELEASED" || !computeReleased.ProviderAbsent ||
		computeReleased.AllocationID != e.AllocationID ||
		computeReleased.ProviderUID != e.ProviderUID ||
		computeReleased.ProviderGeneration != e.ProviderGeneration ||
		computeReleased.ObservedAt.Before(guardReleased.ObservedAt) {
		return reject("G04: Compute provider identity or absence not confirmed")
	}
	return nil
}

// DigestRaw exposes content-addressing for original bytes; it is not itself
// an authenticity proof and MUST always be paired with signature validation.
func DigestRaw(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}
