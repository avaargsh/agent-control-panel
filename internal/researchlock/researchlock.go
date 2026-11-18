// Package researchlock freezes the DAS artifact selected for an ACP RunIntent.
// Callers MUST obtain PublishedRelease and Entitlement from authenticated,
// authoritative server-side stores; this package does not authenticate them.
package researchlock

import (
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidBinding = errors.New("invalid research capability binding")
	ErrUnauthorized   = errors.New("research capability entitlement not active")
	ErrReplayConflict = errors.New("run intent capability lock replay conflict")
)

type ReleaseStatus string

const Published ReleaseStatus = "PUBLISHED"

// Request is the ACP-owned launch identity, not an HTTP authorization claim.
type Request struct {
	TenantID         string
	PrincipalID      string
	RunIntentID      string
	AgentReleaseID   string
	WorkspaceID      string
	SessionID        string
	PackageID        string
	RequestedVersion string // empty means the trusted registry selected the version
}

// PublishedRelease is read from the trusted immutable DAS release catalog.
type PublishedRelease struct {
	PackageID      string
	Version        string
	ArtifactDigest string
	Status         ReleaseStatus
}

// Entitlement is read from the authoritative, authenticated entitlement store.
// Revocation checks for an already running task must happen at execution time.
type Entitlement struct {
	TenantID       string
	PrincipalID    string
	PackageID      string
	SubscriptionID string
	PolicyRevision string
	ValidFrom      time.Time
	ValidUntil     time.Time
	Revoked        bool
}

// Lock is the immutable-by-persistence projection bound to one RunIntent.
// The owning store must persist it atomically with the RunIntent and reject
// conflicting replay; Go struct fields alone do not enforce immutability.
type Lock struct {
	TenantID       string
	PrincipalID    string
	RunIntentID    string
	AgentReleaseID string
	WorkspaceID    string
	SessionID      string
	PackageID      string
	Version        string
	ArtifactDigest string
	SubscriptionID string
	PolicyRevision string
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > 128 || s[0] == '.' || s[0] == '-' || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func validDigest(d string) bool {
	if len(d) != len("sha256:")+64 || !strings.HasPrefix(d, "sha256:") {
		return false
	}
	sum := strings.TrimPrefix(d, "sha256:")
	if strings.ToLower(sum) != sum {
		return false
	}
	_, err := hex.DecodeString(sum)
	return err == nil
}

func (l Lock) Validate() error {
	for _, id := range []string{
		l.TenantID, l.PrincipalID, l.RunIntentID, l.AgentReleaseID, l.WorkspaceID, l.SessionID,
		l.PackageID, l.Version, l.SubscriptionID, l.PolicyRevision,
	} {
		if !validID(id) {
			return ErrInvalidBinding
		}
	}
	if !validDigest(l.ArtifactDigest) {
		return ErrInvalidBinding
	}
	return nil
}

// Resolve freezes the selected immutable published artifact for a fresh RunIntent.
// This is a domain check only. Server-side authorization, catalog authenticity,
// transactional persistence, and active-run revocation are separate gates.
func Resolve(req Request, release PublishedRelease, grant Entitlement, now time.Time) (Lock, error) {
	if !validID(req.TenantID) || !validID(req.PrincipalID) || !validID(req.RunIntentID) ||
		!validID(req.AgentReleaseID) || !validID(req.WorkspaceID) || !validID(req.SessionID) ||
		!validID(req.PackageID) || (req.RequestedVersion != "" && !validID(req.RequestedVersion)) ||
		!validID(release.PackageID) || !validID(release.Version) || !validDigest(release.ArtifactDigest) ||
		release.Status != Published || release.PackageID != req.PackageID ||
		(req.RequestedVersion != "" && req.RequestedVersion != release.Version) ||
		!validID(grant.TenantID) || !validID(grant.PrincipalID) || !validID(grant.PackageID) ||
		!validID(grant.SubscriptionID) || !validID(grant.PolicyRevision) ||
		grant.TenantID != req.TenantID || grant.PrincipalID != req.PrincipalID || grant.PackageID != req.PackageID ||
		now.IsZero() || grant.ValidFrom.IsZero() || grant.ValidUntil.IsZero() ||
		!grant.ValidFrom.Before(grant.ValidUntil) {
		return Lock{}, ErrInvalidBinding
	}
	if grant.Revoked || now.Before(grant.ValidFrom) || !now.Before(grant.ValidUntil) {
		return Lock{}, ErrUnauthorized
	}
	return Lock{
		TenantID: req.TenantID, PrincipalID: req.PrincipalID, RunIntentID: req.RunIntentID,
		AgentReleaseID: req.AgentReleaseID, WorkspaceID: req.WorkspaceID, SessionID: req.SessionID,
		PackageID: release.PackageID, Version: release.Version, ArtifactDigest: release.ArtifactDigest,
		SubscriptionID: grant.SubscriptionID, PolicyRevision: grant.PolicyRevision,
	}, nil
}

// CheckReplay permits an exact replay and rejects any changed release, identity
// or entitlement evidence. Call this under the owning store's uniqueness lock.
func CheckReplay(existing, proposed Lock) error {
	if existing.Validate() != nil || proposed.Validate() != nil {
		return ErrInvalidBinding
	}
	if existing != proposed {
		return ErrReplayConflict
	}
	return nil
}
