package researchlock

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func fixture() (Request, PublishedRelease, Entitlement, time.Time) {
	now := time.Date(2026, 11, 14, 13, 0, 0, 0, time.UTC)
	return Request{
			TenantID: "tenant-a", PrincipalID: "user-a", RunIntentID: "intent-1",
			AgentReleaseID: "agent-release-1", WorkspaceID: "workspace-1", SessionID: "session-1",
			PackageID: "equity-research", RequestedVersion: "1.2.0",
		}, PublishedRelease{
			PackageID: "equity-research", Version: "1.2.0", ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
			Status: Published,
		}, Entitlement{
			TenantID: "tenant-a", PrincipalID: "user-a", PackageID: "equity-research",
			SubscriptionID: "subscription-1", PolicyRevision: "policy-3",
			ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
		}, now
}

func TestResolvePinsExactPublishedArtifactAndScopedEntitlement(t *testing.T) {
	req, release, entitlement, now := fixture()
	pinned, err := Resolve(req, release, entitlement, now)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if pinned.RunIntentID != req.RunIntentID || pinned.WorkspaceID != req.WorkspaceID ||
		pinned.SessionID != req.SessionID || pinned.AgentReleaseID != req.AgentReleaseID ||
		pinned.PackageID != release.PackageID || pinned.Version != release.Version ||
		pinned.ArtifactDigest != release.ArtifactDigest || pinned.PolicyRevision != entitlement.PolicyRevision {
		t.Fatalf("lost immutable launch binding: %+v", pinned)
	}
	if err := CheckReplay(pinned, pinned); err != nil {
		t.Fatalf("same lock must replay: %v", err)
	}
	tampered := pinned
	tampered.ArtifactDigest = "sha256:" + strings.Repeat("b", 64)
	if err := CheckReplay(pinned, tampered); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("same run cannot silently upgrade DAS: %v", err)
	}
}

func TestResolveFailsClosedOnScopeOrReleaseMismatches(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Request, *PublishedRelease, *Entitlement)
	}{
		{"tenant mismatch", func(r *Request, p *PublishedRelease, e *Entitlement) { e.TenantID = "tenant-b" }},
		{"principal mismatch", func(r *Request, p *PublishedRelease, e *Entitlement) { e.PrincipalID = "user-b" }},
		{"package mismatch", func(r *Request, p *PublishedRelease, e *Entitlement) { e.PackageID = "other" }},
		{"release mismatch", func(r *Request, p *PublishedRelease, e *Entitlement) { p.PackageID = "other" }},
		{"requested version mismatch", func(r *Request, p *PublishedRelease, e *Entitlement) { r.RequestedVersion = "1.3.0" }},
		{"unpublished release", func(r *Request, p *PublishedRelease, e *Entitlement) { p.Status = "DRAFT" }},
		{"missing policy revision", func(r *Request, p *PublishedRelease, e *Entitlement) { e.PolicyRevision = "" }},
		{"invalid sha digest", func(r *Request, p *PublishedRelease, e *Entitlement) {
			p.ArtifactDigest = "sha256:" + strings.Repeat("G", 64)
		}},
		{"path-like package ID", func(r *Request, p *PublishedRelease, e *Entitlement) {
			r.PackageID = "../equity-research"
			p.PackageID = r.PackageID
			e.PackageID = r.PackageID
		}},
		{"empty workspace", func(r *Request, p *PublishedRelease, e *Entitlement) { r.WorkspaceID = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, release, entitlement, now := fixture()
			tc.mutate(&req, &release, &entitlement)
			if _, err := Resolve(req, release, entitlement, now); !errors.Is(err, ErrInvalidBinding) {
				t.Fatalf("bad binding should be rejected, got %v", err)
			}
		})
	}
}

func TestResolveRejectsExpiredNotYetValidOrRevokedEntitlements(t *testing.T) {
	req, release, entitlement, now := fixture()
	if _, err := Resolve(req, release, entitlement, entitlement.ValidFrom); err != nil {
		t.Fatalf("valid from is inclusive: %v", err)
	}
	if _, err := Resolve(req, release, entitlement, entitlement.ValidUntil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("valid until is exclusive: %v", err)
	}
	if _, err := Resolve(req, release, entitlement, entitlement.ValidFrom.Add(-time.Nanosecond)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("premature grant allowed: %v", err)
	}
	entitlement.Revoked = true
	if _, err := Resolve(req, release, entitlement, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked grant allowed: %v", err)
	}
}

func TestReplayRejectsChangedScopeAndSubscriptionEvidence(t *testing.T) {
	req, release, entitlement, now := fixture()
	pinned, err := Resolve(req, release, entitlement, now)
	if err != nil {
		t.Fatal(err)
	}
	changed := pinned
	changed.WorkspaceID = "workspace-2"
	if err := CheckReplay(pinned, changed); !errors.Is(err, ErrReplayConflict) {
		t.Fatal(err)
	}
	changed = pinned
	changed.PolicyRevision = "policy-4"
	if err := CheckReplay(pinned, changed); !errors.Is(err, ErrReplayConflict) {
		t.Fatal(err)
	}
	changed = pinned
	changed.RunIntentID = "intent-2"
	if err := CheckReplay(pinned, changed); !errors.Is(err, ErrReplayConflict) {
		t.Fatal(err)
	}
}
