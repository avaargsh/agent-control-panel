package admission

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

const RunIntentCreateScope = "acp:run-intent:create"
const MaxPolicySnapshotLifetime = time.Hour

var (
	ErrPolicyDenied      = errors.New("RunIntent admission denied by policy")
	ErrPolicyUnavailable = errors.New("RunIntent admission policy unavailable or expired")
	ErrPolicyConfig      = errors.New("invalid RunIntent admission policy snapshot")
)

// PolicyEntry is a trusted operator-provided direct-subject allowlist entry,
// not caller input or a protected action permit. All resource IDs are exact.
// Delegated actors and wildcard grants are deliberately unsupported.
type PolicyEntry struct {
	Issuer       string
	Subject      string
	ClientID     string
	Target       Target
	PrincipalID  string
	SubjectID    string
	ConfigDigest string
}

// PolicySnapshot is a bounded-lifetime configuration from the ACP resource
// authority. This initial implementation has no catalog writer, dynamic
// revocation channel or cross-process policy freshness guarantee.
type PolicySnapshot struct {
	Revision  string
	ExpiresAt time.Time
	Grants    []PolicyEntry
}

type exactKey struct {
	issuer, subject, client string
	target                  Target
}

type releaseKey struct {
	tenant, project, agent, release string
}

type subjectKey struct {
	issuer, subject, tenant string
}

type subjectBinding struct {
	principal, subject string
}

type ExactPolicy struct {
	revision  string
	expiresAt time.Time
	grants    map[exactKey]PolicyEntry
}

// NewExactPolicy copies a trusted snapshot; invalid or ambiguous configuration
// fails closed. Reload/revocation is not implicit: the host must replace this
// authority with a fresh verified snapshot before the expiry deadline.
func NewExactPolicy(snapshot PolicySnapshot) (*ExactPolicy, error) {
	now := time.Now()
	if !validPolicyID(snapshot.Revision) || !snapshot.ExpiresAt.After(now) ||
		snapshot.ExpiresAt.Sub(now) > MaxPolicySnapshotLifetime ||
		len(snapshot.Grants) > 10000 {
		return nil, ErrPolicyConfig
	}
	policy := &ExactPolicy{
		revision: snapshot.Revision, expiresAt: snapshot.ExpiresAt,
		grants: make(map[exactKey]PolicyEntry, len(snapshot.Grants)),
	}
	releases := make(map[releaseKey]string)
	subjects := make(map[subjectKey]subjectBinding)
	for _, entry := range snapshot.Grants {
		t := entry.Target
		principal := runintent.PrincipalSnapshot{
			Version: runintent.PrincipalSnapshotVersion, ProjectID: t.ProjectID,
			SubjectID: entry.SubjectID, ActorID: entry.SubjectID,
			PolicyRevision: snapshot.Revision, ConfigDigest: entry.ConfigDigest,
		}
		if !validHTTPS(entry.Issuer) || !validIdentityValue(entry.Subject) ||
			!validIdentityValue(entry.ClientID) || !validPolicyID(entry.PrincipalID) ||
			!validPolicyID(entry.SubjectID) || !validPolicyID(t.TenantID) ||
			!validPolicyID(t.ProjectID) || !validPolicyID(t.AgentID) ||
			!validPolicyID(t.ReleaseID) || !validPolicyID(t.SessionID) ||
			principal.ValidateForProject(t.ProjectID) != nil {
			return nil, ErrPolicyConfig
		}
		key := exactKey{entry.Issuer, entry.Subject, entry.ClientID, t}
		if _, exists := policy.grants[key]; exists {
			return nil, ErrPolicyConfig
		}
		release := releaseKey{t.TenantID, t.ProjectID, t.AgentID, t.ReleaseID}
		if digest, exists := releases[release]; exists && digest != entry.ConfigDigest {
			return nil, ErrPolicyConfig
		}
		releases[release] = entry.ConfigDigest
		subject := subjectKey{entry.Issuer, entry.Subject, t.TenantID}
		binding := subjectBinding{entry.PrincipalID, entry.SubjectID}
		if stored, exists := subjects[subject]; exists && stored != binding {
			return nil, ErrPolicyConfig
		}
		subjects[subject] = binding
		policy.grants[key] = entry
	}
	return policy, nil
}

func validPolicyID(v string) bool {
	return validIdentityValue(v) && !strings.ContainsAny(v, " *")
}

// RFC 6749 scope-token ASCII grammar. Reject ambiguous separators and never
// use a prefix or substring test to grant a permission.
func validOAuthScope(scope string) bool {
	if scope == "" || len(scope) > 4096 {
		return false
	}
	for _, token := range strings.Split(scope, " ") {
		if token == "" {
			return false
		}
		for _, c := range []byte(token) {
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return false
			}
		}
	}
	return true
}

func hasCreateScope(scope string) bool {
	if !validOAuthScope(scope) {
		return false
	}
	for _, token := range strings.Split(scope, " ") {
		if token == RunIntentCreateScope {
			return true
		}
	}
	return false
}

func (p *ExactPolicy) Authorize(ctx context.Context, id Identity, req Request) (Grant, error) {
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}
	now := time.Now()
	if p == nil || !p.expiresAt.After(now) {
		return Grant{}, ErrPolicyUnavailable
	}
	if !id.ExpiresAt.After(now) {
		return Grant{}, ErrUnauthenticated
	}
	if !req.inputBound || !hasCreateScope(id.Scope) {
		return Grant{}, ErrPolicyDenied
	}
	entry, ok := p.grants[exactKey{id.Issuer, id.Subject, id.ClientID, req.Target}]
	if !ok {
		return Grant{}, ErrPolicyDenied
	}
	// Digest was computed by ACP from actual bytes before this method.
	// Identity and immutable release evidence come only from the snapshot.
	return Grant{
		Target: entry.Target, RequestDigest: req.RequestDigest, PrincipalID: entry.PrincipalID,
		Snapshot: runintent.PrincipalSnapshot{
			Version: runintent.PrincipalSnapshotVersion, ProjectID: entry.Target.ProjectID,
			SubjectID: entry.SubjectID, ActorID: entry.SubjectID,
			PolicyRevision: p.revision, ConfigDigest: entry.ConfigDigest,
		},
	}, nil
}

var _ PolicyAuthority = (*ExactPolicy)(nil)
