package authorityhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

// GuardProtectedWorkspaceSchema is deliberately separate from the read-only
// Decision/SRE capability publication. It is never a Scoped Permit.
const GuardProtectedWorkspaceSchema = "acp.guard-protected-workspace.v1"

var (
	ErrProtectedWorkspaceDenied = errors.New("ACP protected workspace release denied")
	protectedWorkspaceDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const protectedWorkspaceMaxLifetime = 15 * time.Minute

// GuardProtectedWorkspaceRequest is untrusted selector data from an already
// authenticated Guard workload. It cannot carry a user credential, policy,
// release body, issuer key or approval/Permit.
type GuardProtectedWorkspaceRequest struct {
	SchemaVersion string `json:"schema_version"`
	RunID string `json:"run_id"`
	AgentID string `json:"agent_id"`
	AgentReleaseID string `json:"agent_release_id"`
	SessionID string `json:"session_id"`
	SubjectID string `json:"subject_id"`
	CapabilityID string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	PolicyRevision string `json:"policy_revision"`
	WorkspaceID string `json:"workspace_id"`
	ToolBindingDigest string `json:"tool_binding_digest"`
	Audience string `json:"audience"`
}

// ProtectedWorkspaceContract is exactly one provisioned work tool version,
// audience and workspace, not an unrestricted wildcard capability.
type ProtectedWorkspaceContract struct {
	ID string `json:"id"`
	Version string `json:"version"`
	EffectClass string `json:"effect_class"`
	Idempotency string `json:"idempotency"`
	TenantScoped bool `json:"tenant_scoped"`
	ApprovalRequired bool `json:"approval_required"`
	ToolBindingDigest string `json:"tool_binding_digest"`
	Audience string `json:"audience"`
	WorkspaceID string `json:"workspace_id"`
}

// ProtectedWorkspaceRelease is an immutable ACP operator-provisioned
// content-addressed Release artifact. Its SHA256 must be the *original*
// ACP/OIDC-admitted Run's currently active config digest, never one provided
// by a Guard ActionSubmission.
type ProtectedWorkspaceRelease struct {
	SchemaVersion string `json:"schema_version"`
	TenantID string `json:"tenant_id"`
	ProjectID string `json:"project_id"`
	AgentID string `json:"agent_id"`
	AgentReleaseID string `json:"agent_release_id"`
	PolicyRevision string `json:"policy_revision"`
	IssuedAt time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Capability ProtectedWorkspaceContract `json:"capability"`
}

// GuardProtectedWorkspaceReceipt is a current read-only catalog observation.
// It is NOT a Permit, is not transferable, and cannot authorize an effect.
type GuardProtectedWorkspaceReceipt struct {
	SchemaVersion string `json:"schema_version"`
	RunID string `json:"run_id"`
	AgentID string `json:"agent_id"`
	AgentReleaseID string `json:"agent_release_id"`
	SessionID string `json:"session_id"`
	SubjectID string `json:"subject_id"`
	CapabilityID string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	ContractSHA256 string `json:"contract_sha256"`
	ConfigDigest string `json:"config_digest"`
	PolicyRevision string `json:"policy_revision"`
	WorkspaceID string `json:"workspace_id"`
	ToolBindingDigest string `json:"tool_binding_digest"`
	Audience string `json:"audience"`
	Status string `json:"status"`
}

type protectedWorkspaceIntent struct {
	Objective string `json:"objective"`
	WorkspaceID string `json:"workspace_id"`
}

// Strict canonical parsing forbids type aliases, unknown/duplicate keys,
// whitespace tricks, and malformed nested JSON even when a digest matches.
func decodeProtectedJSON(raw []byte, max int, dest any) bool {
	if len(raw) < 2 || len(raw) > max || !canonicalObject(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return false
	}
	canonical, err := json.Marshal(dest)
	return err == nil && bytes.Equal(canonical, raw)
}

func (q GuardProtectedWorkspaceRequest) Validate() error {
	for _, id := range []string{q.AgentID, q.AgentReleaseID, q.SessionID,
		q.SubjectID, q.PolicyRevision, q.WorkspaceID, q.Audience} {
		if !publicationID.MatchString(id) {
			return ErrProtectedWorkspaceDenied
		}
	}
	if q.SchemaVersion != GuardProtectedWorkspaceSchema || !idPattern.MatchString(q.RunID) ||
		q.CapabilityID != "workspace.write" || !publicationVersion.MatchString(q.CapabilityVersion) ||
		!protectedWorkspaceDigest.MatchString(q.ToolBindingDigest) {
		return ErrProtectedWorkspaceDenied
	}
	return nil
}

// VerifyProtectedWorkspaceRelease checks a single current original Run+input
// and its immutable ACP Release against separately resolved Guard selectors.
// It MUST only receive the Snapshot and exact raw bytes from live ACP's
// GetGuardRunAuthority query. It has NO business permission, approval, policy
// revocation, Permit issue/claim, executor, or external effect side effects.
func VerifyProtectedWorkspaceRelease(
	a Snapshot, originalInput, releaseBytes []byte, q GuardProtectedWorkspaceRequest, now time.Time,
) (GuardProtectedWorkspaceReceipt, error) {
	denied := func() (GuardProtectedWorkspaceReceipt, error) {
		return GuardProtectedWorkspaceReceipt{}, ErrProtectedWorkspaceDenied
	}
	if now.IsZero() || q.Validate() != nil || a.SchemaVersion != "acp.run-authority.v1" ||
		!idPattern.MatchString(a.RunIntentID) || !idPattern.MatchString(a.RunID) ||
		a.RunID != q.RunID || !digestPattern.MatchString(a.RequestDigest) ||
		!digestPattern.MatchString(a.ConfigDigest) || !publicationID.MatchString(a.TenantID) ||
		!publicationID.MatchString(a.ProjectID) || !publicationID.MatchString(a.PrincipalID) ||
		!publicationID.MatchString(a.SubjectID) || a.ActorID != a.SubjectID ||
		!publicationID.MatchString(a.AgentID) || !publicationID.MatchString(a.AgentReleaseID) ||
		!publicationID.MatchString(a.SessionID) || !publicationID.MatchString(a.PolicyRevision) ||
		a.AgentID != q.AgentID || a.AgentReleaseID != q.AgentReleaseID ||
		a.SessionID != q.SessionID || a.SubjectID != q.SubjectID ||
		a.PolicyRevision != q.PolicyRevision ||
		a.ConfigDigest != "sha256:"+sha256Hex(releaseBytes) {
		return denied()
	}
	var original protectedWorkspaceIntent
	if !decodeProtectedJSON(originalInput, 16384, &original) ||
		original.Objective != "workspace_write" || original.WorkspaceID != q.WorkspaceID {
		return denied()
	}
	var release ProtectedWorkspaceRelease
	if !decodeProtectedJSON(releaseBytes, maxReleaseBytes, &release) ||
		release.SchemaVersion != "acp.protected-workspace-release.v1" ||
		release.TenantID != a.TenantID || release.ProjectID != a.ProjectID ||
		release.AgentID != a.AgentID || release.AgentReleaseID != a.AgentReleaseID ||
		release.PolicyRevision != a.PolicyRevision ||
		release.IssuedAt.IsZero() || release.ExpiresAt.IsZero() ||
		now.Before(release.IssuedAt) || !now.Before(release.ExpiresAt) ||
		!release.ExpiresAt.After(release.IssuedAt) ||
		release.ExpiresAt.Sub(release.IssuedAt) > protectedWorkspaceMaxLifetime {
		return denied()
	}
	c := release.Capability
	if c.ID != "workspace.write" || c.Version != q.CapabilityVersion ||
		c.EffectClass != "protected_write" || c.Idempotency != "guard_permit_once" ||
		!c.TenantScoped || !c.ApprovalRequired ||
		c.WorkspaceID != q.WorkspaceID || !publicationID.MatchString(c.WorkspaceID) ||
		c.ToolBindingDigest != q.ToolBindingDigest ||
		!protectedWorkspaceDigest.MatchString(c.ToolBindingDigest) ||
		c.Audience != q.Audience || !publicationID.MatchString(c.Audience) {
		return denied()
	}
	contractBytes, err := json.Marshal(c)
	if err != nil {
		return denied()
	}
	return GuardProtectedWorkspaceReceipt{
		SchemaVersion: GuardProtectedWorkspaceSchema,
		RunID: a.RunID, AgentID: a.AgentID, AgentReleaseID: a.AgentReleaseID,
		SessionID: a.SessionID, SubjectID: a.SubjectID,
		CapabilityID: c.ID, CapabilityVersion: c.Version,
		ContractSHA256: sha256Hex(contractBytes), ConfigDigest: a.ConfigDigest,
		PolicyRevision: a.PolicyRevision, WorkspaceID: c.WorkspaceID,
		ToolBindingDigest: c.ToolBindingDigest, Audience: c.Audience,
		Status: "VERIFIED",
	}, nil
}
