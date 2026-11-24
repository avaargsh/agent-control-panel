// Package authoritycutover models the ACP catalog cutover transitions only.
// It is not an admission gate, DCL executor, or Guard authorization service.
package authoritycutover

import (
	"encoding/hex"
	"errors"
	"math"
	"strings"
)

type Phase string

const (
	Open      Phase = "OPEN"
	Draining  Phase = "DRAINING"
	Closed    Phase = "CLOSED"
	Verifying Phase = "VERIFYING"
)

type Action string

const (
	Begin          Action = "BEGIN"
	MarkDrained    Action = "MARK_DRAINED"
	ObserveApplied Action = "OBSERVE_APPLIED"
	Reopen         Action = "REOPEN"
)

type Change struct{ ID, ManifestDigest, Operator string }
type Record struct {
	Generation, Revision int64
	Phase                Phase
	Change               Change
}

var (
	ErrConflict = errors.New("cutover conflict")
	ErrInvalid  = errors.New("invalid cutover transition")
)

func (c Change) valid() bool {
	if c.ID == "" || c.Operator == "" || strings.TrimSpace(c.ID) != c.ID || strings.TrimSpace(c.Operator) != c.Operator || len(c.ManifestDigest) != 71 || !strings.HasPrefix(c.ManifestDigest, "sha256:") || strings.ToLower(c.ManifestDigest) != c.ManifestDigest {
		return false
	}
	_, err := hex.DecodeString(c.ManifestDigest[7:])
	return err == nil
}
func (r Record) valid() bool {
	if r.Generation <= 0 || r.Revision < r.Generation {
		return false
	}
	switch r.Phase {
	case Open:
		return r.Change == (Change{}) || r.Change.valid()
	case Draining, Closed, Verifying:
		return r.Change.valid()
	default:
		return false
	}
}

// Advance computes a candidate record, never persists it. A trusted adapter
// must verify external drain/DCL/attestation proofs before supplying actions,
// and commit with an atomic full-record CAS. Do not retry DCL based on this
// function's result; recover uncertain outcomes through authoritative readback.
func Advance(current, expected Record, action Action, change Change) (Record, error) {
	if !current.valid() || !change.valid() || current.Revision == math.MaxInt64 {
		return current, ErrInvalid
	}
	if current != expected {
		return current, ErrConflict
	}
	if action != Begin && current.Change != change {
		return current, ErrConflict
	}
	next := current
	switch {
	case action == Begin && current.Phase == Open:
		if current.Change.ID == change.ID {
			return current, ErrConflict
		}
		next.Phase = Draining
		next.Change = change
	case action == MarkDrained && current.Phase == Draining:
		next.Phase = Closed
	case action == ObserveApplied && current.Phase == Closed:
		if current.Generation == math.MaxInt64 {
			return current, ErrInvalid
		}
		next.Phase = Verifying
		next.Generation++
	case action == Reopen && current.Phase == Verifying:
		next.Phase = Open
	default:
		return current, ErrInvalid
	}
	next.Revision++
	return next, nil
}
