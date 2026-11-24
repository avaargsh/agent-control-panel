package authorityhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

const GuardCapabilityPath = "/internal/v1/guard-capabilities:verify"
const GuardCapabilitySchema = "acp.guard-capability.v1"

// GuardCapabilityRequest only contains selectors. It must NEVER contain the
// tenant, authenticated identity, token, catalog snapshot, or a Permit.
type GuardCapabilityRequest struct {
	SchemaVersion     string `json:"schema_version"`
	RunID             string `json:"run_id"`
	AgentID           string `json:"agent_id"`
	AgentReleaseID    string `json:"agent_release_id"`
	SessionID         string `json:"session_id"`
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	ResourceRef       string `json:"resource_ref"`
}

// GuardCapabilityReceipt is a point-in-time read-only observation, not a
// grant or execution Permit. It is not stable across live policy revocation.
type GuardCapabilityReceipt struct {
	SchemaVersion     string `json:"schema_version"`
	RunID             string `json:"run_id"`
	AgentID           string `json:"agent_id"`
	AgentReleaseID    string `json:"agent_release_id"`
	SessionID         string `json:"session_id"`
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	ContractSHA256    string `json:"contract_sha256"`
	PolicyRevision    string `json:"policy_revision"`
	ResourceRef       string `json:"resource_ref"`
	Status            string `json:"status"`
}

var ErrGuardCapabilityDenied = errors.New("ACP Guard capability denied")

func (q GuardCapabilityRequest) Validate() error {
	if q.SchemaVersion != GuardCapabilitySchema || !idPattern.MatchString(q.RunID) ||
		!publicationID.MatchString(q.AgentID) || !publicationID.MatchString(q.AgentReleaseID) ||
		!publicationID.MatchString(q.SessionID) || !publicationID.MatchString(q.CapabilityID) ||
		!publicationVersion.MatchString(q.CapabilityVersion) ||
		!publicationID.MatchString(q.ResourceRef) {
		return ErrGuardCapabilityDenied
	}
	return nil
}

// publishedGuardBindingsIntact re-derives all capability references from
// the immutable release bytes and binds the context to its exact signed
// bytes. This is defense in depth: the HTTP handler must still freshly read
// ACP admission/catalog authority, publish, and authenticate the Guard peer.
// It is NOT an independent grant, Permit or revocation-safe PEP check.
func publishedGuardBindingsIntact(p Publication) bool {
	contextBytes, err := json.Marshal(p.Context)
	if err != nil || !bytes.Equal(contextBytes, p.ContextContent) ||
		p.Authority.ConfigDigest != "sha256:"+sha256Hex(p.CapabilityContent) {
		return false
	}
	config, err := decodeRelease(p.CapabilityContent)
	if err != nil || config.SchemaVersion != "acp.release-publication.v1" ||
		config.TenantID != p.Authority.TenantID ||
		config.ProjectID != p.Authority.ProjectID ||
		config.AgentID != p.Authority.AgentID ||
		config.AgentReleaseID != p.Authority.AgentReleaseID ||
		config.PolicyRevision != p.Authority.PolicyRevision ||
		len(config.Capabilities) != len(p.Capabilities) {
		return false
	}
	for i, contract := range config.Capabilities {
		expected, err := capabilityReference(contract)
		if err != nil || p.Capabilities[i] != expected {
			return false
		}
	}
	return true
}

// MatchGuardCapability only compares to ACP's *freshly constructed* signed
// publication. The handler must first resolve the authentic original
// admission and current release bytes; this pure helper is not authority.
func MatchGuardCapability(p Publication, q GuardCapabilityRequest) (GuardCapabilityReceipt, error) {
	var empty GuardCapabilityReceipt
	a := p.Authority
	if q.Validate() != nil || p.SchemaVersion != publicationSchema ||
		a.SchemaVersion != "acp.run-authority.v1" || a.RunID != q.RunID ||
		a.AgentID != q.AgentID || a.AgentReleaseID != q.AgentReleaseID ||
		a.SessionID != q.SessionID || a.PolicyRevision == "" ||
		p.Context.Authority != a || p.Context.Service != q.ResourceRef ||
		p.CapabilitySnapshot.SHA256 != sha256Hex(p.CapabilityContent) ||
		p.ContextSnapshot.SHA256 != sha256Hex(p.ContextContent) ||
		!publishedGuardBindingsIntact(p) {
		return empty, ErrGuardCapabilityDenied
	}
	var matched *CapabilityRef
	for i := range p.Capabilities {
		c := &p.Capabilities[i]
		if c.ID == q.CapabilityID && c.Version == q.CapabilityVersion {
			if matched != nil {
				return empty, ErrGuardCapabilityDenied
			}
			matched = c
		}
	}
	if matched == nil || matched.EffectClass != "read_only" ||
		matched.Idempotency != "safe" || !matched.TenantScoped ||
		!publicationID.MatchString(matched.ID) || !publicationVersion.MatchString(matched.Version) ||
		len(matched.ContractSHA256) != 64 || !strings.HasPrefix(matched.InputSchemaRef, "sha256:") ||
		!strings.HasPrefix(matched.OutputSchemaRef, "sha256:") {
		return empty, ErrGuardCapabilityDenied
	}
	return GuardCapabilityReceipt{
		SchemaVersion: GuardCapabilitySchema, RunID: a.RunID,
		AgentID: a.AgentID, AgentReleaseID: a.AgentReleaseID, SessionID: a.SessionID,
		CapabilityID: matched.ID, CapabilityVersion: matched.Version,
		ContractSHA256: matched.ContractSHA256, PolicyRevision: a.PolicyRevision,
		ResourceRef: q.ResourceRef, Status: "VERIFIED",
	}, nil
}

type GuardCapabilityReader interface {
	GetGuardRunAuthority(context.Context, string, string) (runpg.ExecutionAuthority, []byte, error)
}

// NewGuardCapabilityHandler MUST be hosted on an independent Guard-only
// TLS 1.3 listener with RequireAndVerifyClientCert, not the Runtime/Decision
// authority listener. The certificate identity and tenant are operator pins.
func NewGuardCapabilityHandler(
	reader GuardCapabilityReader, publisher *Publisher, guardPeer, tenant string,
) (http.Handler, error) {
	if nilReaderInterface(reader) || publisher == nil || publisher.root == nil ||
		!validIdentity(guardPeer) || !validTenant(tenant) {
		return nil, ErrPublicationUnavailable
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fail := func(status int, code string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
		}
		if !verifiedPeer(r.TLS, guardPeer) {
			fail(http.StatusUnauthorized, "UNAUTHENTICATED")
			return
		}
		if r.URL.Path != GuardCapabilityPath || r.URL.RawPath != "" ||
			r.URL.RawQuery != "" || r.URL.ForceQuery || r.Method != http.MethodPost {
			fail(http.StatusNotFound, "NOT_FOUND")
			return
		}
		if values := r.Header.Values("Content-Type"); len(values) != 1 || values[0] != "application/json" || r.Body == nil {
			fail(http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		defer r.Body.Close()
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
		var q GuardCapabilityRequest
		if err != nil || json.Unmarshal(raw, &q) != nil || q.Validate() != nil {
			fail(http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		canonical, err := json.Marshal(q)
		if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
			fail(http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		current, input, err := reader.GetGuardRunAuthority(ctx, tenant, q.RunID)
		if ctx.Err() != nil {
			fail(http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE")
			return
		}
		if errors.Is(err, runpg.ErrCatalogDenied) {
			fail(http.StatusForbidden, "CAPABILITY_DENIED")
			return
		}
		if err != nil || current.Ref.TenantID != tenant || current.Ref.RunID != q.RunID ||
			current.PrincipalID == "" || current.ReleaseID == "" ||
			current.Snapshot.ValidateForProject(current.Snapshot.ProjectID) != nil {
			fail(http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE")
			return
		}
		snapshot := Snapshot{
			SchemaVersion: "acp.run-authority.v1", TenantID: tenant,
			RunIntentID: current.Ref.RunIntentID, RequestDigest: current.Ref.RequestDigest,
			RunID: q.RunID, ProjectID: current.Snapshot.ProjectID,
			AgentID: current.AgentID, AgentReleaseID: current.ReleaseID,
			SessionID: current.SessionID, PrincipalID: current.PrincipalID,
			SubjectID: current.Snapshot.SubjectID, ActorID: current.Snapshot.ActorID,
			PolicyRevision: current.Snapshot.PolicyRevision, ConfigDigest: current.Snapshot.ConfigDigest,
		}
		publication, err := publisher.Publish(snapshot, input, time.Now().UTC())
		if ctx.Err() != nil {
			fail(http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE")
			return
		}
		if errors.Is(err, ErrPublicationDenied) {
			fail(http.StatusForbidden, "CAPABILITY_DENIED")
			return
		}
		if err != nil {
			fail(http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE")
			return
		}
		var decoded Publication
		if err := json.Unmarshal(publication.Payload, &decoded); err != nil {
			fail(http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE")
			return
		}
		receipt, err := MatchGuardCapability(decoded, q)
		if ctx.Err() != nil {
			fail(http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE")
			return
		}
		if err != nil {
			fail(http.StatusForbidden, "CAPABILITY_DENIED")
			return
		}
		_ = json.NewEncoder(w).Encode(receipt)
	}), nil
}
