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

const GuardProtectedWorkspacePath = "/internal/v1/guard-protected-workspaces:verify"

// ObserveProtectedWorkspace reads only the exact original Run's currently
// pinned content-addressed release file. A verified response is a point-in-time
// necessary catalog observation, never authority to execute or issue a Permit.
func (p *Publisher) ObserveProtectedWorkspace(
	a Snapshot, originalInput []byte, q GuardProtectedWorkspaceRequest, now time.Time,
) (GuardProtectedWorkspaceReceipt, error) {
	if p == nil || p.root == nil || !digestPattern.MatchString(a.ConfigDigest) {
		return GuardProtectedWorkspaceReceipt{}, ErrPublicationUnavailable
	}
	file, err := p.root.Open(strings.TrimPrefix(a.ConfigDigest, "sha256:") + ".json")
	if err != nil {
		return GuardProtectedWorkspaceReceipt{}, ErrPublicationUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxReleaseBytes {
		return GuardProtectedWorkspaceReceipt{}, ErrPublicationUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxReleaseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxReleaseBytes ||
		"sha256:"+sha256Hex(raw) != a.ConfigDigest {
		return GuardProtectedWorkspaceReceipt{}, ErrPublicationUnavailable
	}
	return VerifyProtectedWorkspaceRelease(a, originalInput, raw, q, now)
}

// NewGuardProtectedWorkspaceHandler runs behind the *separate* Guard-only
// TLS1.3 listener. The only accepted caller is its pinned, verified mTLS
// workload identity and configured tenant, not any forwarded HTTP header.
// No untrusted caller can select an Intent ID, role, config digest or tenant.
func NewGuardProtectedWorkspaceHandler(
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
		if r.URL.Path != GuardProtectedWorkspacePath || r.URL.RawPath != "" ||
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
		var q GuardProtectedWorkspaceRequest
		if err != nil || json.Unmarshal(raw, &q) != nil || q.Validate() != nil {
			fail(http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		canonical, err := json.Marshal(q)
		if err != nil || !bytes.Equal(raw, canonical) {
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
		a := Snapshot{
			SchemaVersion: "acp.run-authority.v1", TenantID: tenant,
			RunIntentID: current.Ref.RunIntentID, RunID: q.RunID,
			RequestDigest: current.Ref.RequestDigest,
			ProjectID:     current.Snapshot.ProjectID,
			AgentID:       current.AgentID, AgentReleaseID: current.ReleaseID,
			SessionID: current.SessionID, PrincipalID: current.PrincipalID,
			SubjectID: current.Snapshot.SubjectID, ActorID: current.Snapshot.ActorID,
			PolicyRevision: current.Snapshot.PolicyRevision,
			ConfigDigest:   current.Snapshot.ConfigDigest,
		}
		receipt, err := publisher.ObserveProtectedWorkspace(a, input, q, time.Now().UTC())
		if ctx.Err() != nil {
			fail(http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE")
			return
		}
		if errors.Is(err, ErrProtectedWorkspaceDenied) {
			fail(http.StatusForbidden, "CAPABILITY_DENIED")
			return
		}
		if err != nil {
			fail(http.StatusServiceUnavailable, "AUTHORITY_UNAVAILABLE")
			return
		}
		_ = json.NewEncoder(w).Encode(receipt)
	}), nil
}
