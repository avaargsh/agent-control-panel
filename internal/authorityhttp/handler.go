// Package authorityhttp exposes a read-only ACP catalog authority boundary.
// It authenticates a configured workload and tenant; it is not a user API,
// independent Evidence publisher, Guard Permit issuer or execution endpoint.
package authorityhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

const PathPrefix = "/internal/v1/run-authority/"
const PublicationPathPrefix = "/internal/v1/decision-publication/"

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Reader interface {
	GetExecutionAuthority(context.Context, runpg.ExecutionAuthorityRef) (runpg.ExecutionAuthority, error)
}

type PublicationReader interface {
	Reader
	GetExecutionAuthorityInput(context.Context, runpg.ExecutionAuthorityRef) (runpg.ExecutionAuthority, []byte, error)
}

type Snapshot struct {
	SchemaVersion  string `json:"schema_version"`
	TenantID       string `json:"tenant_id"`
	RunIntentID    string `json:"run_intent_id"`
	RunID          string `json:"run_id"`
	RequestDigest  string `json:"request_digest"`
	ProjectID      string `json:"project_id"`
	AgentID        string `json:"agent_id"`
	AgentReleaseID string `json:"agent_release_id"`
	SessionID      string `json:"session_id"`
	PrincipalID    string `json:"principal_id"`
	SubjectID      string `json:"subject_id"`
	ActorID        string `json:"actor_id"`
	PolicyRevision string `json:"policy_revision"`
	ConfigDigest   string `json:"config_digest"`
}

func validIdentity(id string) bool {
	u, err := url.Parse(id)
	return err == nil && u.Scheme == "spiffe" && u.Host != "" && u.Path != "" &&
		u.User == nil && u.Opaque == "" && u.RawPath == "" && u.RawQuery == "" &&
		!u.ForceQuery && u.Fragment == "" && u.String() == id
}

func validTenant(tenant string) bool {
	return tenant != "" && len(tenant) <= 255 && strings.TrimSpace(tenant) == tenant &&
		utf8.ValidString(tenant) && !strings.ContainsAny(tenant, "\x00\r\n\t ")
}

func verifiedPeer(state *tls.ConnectionState, peer string) bool {
	if state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 ||
		len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return false
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || leaf.IsCA || len(leaf.Raw) == 0 || len(leaf.URIs) != 1 ||
		leaf.URIs[0] == nil || leaf.URIs[0].String() != peer ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return false
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) != 0 && chain[0] != nil && chain[0].Equal(leaf) {
			return true
		}
	}
	return false
}

func nilReader(reader Reader) bool {
	if reader == nil {
		return true
	}
	v := reflect.ValueOf(reader)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// NewHandler must be hosted behind a real TLS listener that uses
// RequireAndVerifyClientCert and the dedicated trust-domain CA. The exact
// workload and tenant are provisioned out-of-band, never request claims.
func NewHandler(reader Reader, peer, tenant string) (http.Handler, error) {
	return newHandler(reader, nil, peer, tenant)
}

// NewPublicationHandler serves both existing authority and signed
// publication reads, under the same independent mTLS trust boundary.
func NewPublicationHandler(reader PublicationReader, publisher *Publisher, peer, tenant string) (http.Handler, error) {
	if publisher == nil || publisher.root == nil {
		return nil, ErrPublicationUnavailable
	}
	return newHandler(reader, publisher, peer, tenant)
}

func newHandler(reader Reader, publisher *Publisher, peer, tenant string) (http.Handler, error) {
	if nilReader(reader) || !validIdentity(peer) || !validTenant(tenant) {
		return nil, errors.New("invalid ACP execution authority configuration")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		fail := func(status int, code string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
		}
		if !verifiedPeer(r.TLS, peer) {
			fail(http.StatusUnauthorized, "UNAUTHENTICATED")
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			fail(http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		prefix := PathPrefix
		publication := strings.HasPrefix(r.URL.Path, PublicationPathPrefix)
		if publication {
			if publisher == nil {
				fail(http.StatusServiceUnavailable, "PUBLICATION_UNAVAILABLE")
				return
			}
			prefix = PublicationPathPrefix
		}
		intentID := strings.TrimPrefix(r.URL.Path, prefix)
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || r.URL.RawPath != "" || r.URL.ForceQuery || !strings.HasPrefix(r.URL.Path, prefix) ||
			!idPattern.MatchString(intentID) || len(query) != 2 ||
			len(query["run_id"]) != 1 || len(query["request_digest"]) != 1 ||
			!idPattern.MatchString(query.Get("run_id")) || !digestPattern.MatchString(query.Get("request_digest")) ||
			r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			fail(http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if r.Body != nil {
			if raw, err := io.ReadAll(io.LimitReader(r.Body, 1)); err != nil || len(raw) != 0 {
				fail(http.StatusBadRequest, "INVALID_REQUEST")
				return
			}
		}
		ref := runpg.ExecutionAuthorityRef{
			TenantID: tenant, RunIntentID: intentID, RunID: query.Get("run_id"),
			RequestDigest: query.Get("request_digest"),
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		var current runpg.ExecutionAuthority
		var input []byte
		if publication {
			current, input, err = reader.(PublicationReader).GetExecutionAuthorityInput(ctx, ref)
		} else {
			current, err = reader.GetExecutionAuthority(ctx, ref)
		}
		if errors.Is(err, runpg.ErrCatalogDenied) {
			fail(http.StatusForbidden, "RUN_AUTHORITY_DENIED")
			return
		}
		if err != nil || current.Ref != ref || current.PrincipalID == "" ||
			current.AgentID == "" || current.ReleaseID == "" || current.SessionID == "" ||
			current.Snapshot.ValidateForProject(current.Snapshot.ProjectID) != nil {
			fail(http.StatusServiceUnavailable, "RUN_AUTHORITY_UNAVAILABLE")
			return
		}
		snapshot := Snapshot{
			SchemaVersion: "acp.run-authority.v1", TenantID: tenant, RunIntentID: ref.RunIntentID,
			RunID: ref.RunID, RequestDigest: ref.RequestDigest, ProjectID: current.Snapshot.ProjectID,
			AgentID: current.AgentID, AgentReleaseID: current.ReleaseID, SessionID: current.SessionID,
			PrincipalID: current.PrincipalID, SubjectID: current.Snapshot.SubjectID, ActorID: current.Snapshot.ActorID,
			PolicyRevision: current.Snapshot.PolicyRevision, ConfigDigest: current.Snapshot.ConfigDigest,
		}
		if publication {
			got, err := publisher.Publish(snapshot, input, time.Now().UTC())
			switch {
			case errors.Is(err, ErrPublicationDenied):
				fail(http.StatusForbidden, "PUBLICATION_DENIED")
			case err != nil:
				fail(http.StatusServiceUnavailable, "PUBLICATION_UNAVAILABLE")
			default:
				_ = json.NewEncoder(w).Encode(got)
			}
			return
		}
		_ = json.NewEncoder(w).Encode(snapshot)
	}), nil
}
