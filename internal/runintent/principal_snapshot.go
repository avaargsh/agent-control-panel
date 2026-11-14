package runintent

import (
	"errors"
	"strings"
)

const PrincipalSnapshotVersion = "acp-principal/v1"

var (
	ErrPrincipalSnapshotUnavailable = errors.New("RunIntent principal snapshot unavailable")
	ErrPrincipalSnapshotInvalid     = errors.New("invalid RunIntent principal snapshot")
)

// PrincipalSnapshot is captured by ACP admission and stored atomically with
// the RunIntent. It contains the identity/policy assertion already resolved by
// the ACP authority; it is never populated from an untrusted dispatch payload.
// Runtime derives issuer identity from the verified mTLS peer, not this value.
type PrincipalSnapshot struct {
	Version        string
	ProjectID      string
	SubjectID      string
	ActorID        string
	PolicyRevision string
	ConfigDigest   string
}

func (p PrincipalSnapshot) IsZero() bool {
	return p == (PrincipalSnapshot{})
}

// ValidateForProject verifies snapshot shape and its binding to the immutable
// RunIntent project. A zero value means a legacy/unverified record.
func (p PrincipalSnapshot) ValidateForProject(projectID string) error {
	if p.IsZero() {
		return ErrPrincipalSnapshotUnavailable
	}
	if p.Version != PrincipalSnapshotVersion ||
		!validOpaqueID(projectID) ||
		p.ProjectID != projectID ||
		!validOpaqueID(p.ProjectID) ||
		!validOpaqueID(p.SubjectID) ||
		!validOpaqueID(p.ActorID) ||
		!validOpaqueID(p.PolicyRevision) ||
		!validDigest(p.ConfigDigest) ||
		strings.ContainsAny(p.ConfigDigest, " \t\r\n\x00") {
		return ErrPrincipalSnapshotInvalid
	}
	return nil
}
