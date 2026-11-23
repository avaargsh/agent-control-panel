// Package goalhttp exposes only authenticated, non-dispatch Issue Goal
// admission. Its host must independently configure TLS, OAuth/CatalogPolicy,
// PostgreSQL and the trusted source verifier; there are no safe defaults.
package goalhttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"

	"github.com/avaargsh/agent-control-panel/internal/admission"
	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

const (
	SubmitPath        = "/api/v1/goals:submit"
	StatusPath        = "/api/v1/goals:status"
	AcceptanceVersion = "acp.issue-goal-acceptance/v1"
	StatusVersion     = "acp.issue-goal-status/v1"
)

type GoalAdmitter interface {
	AdmitPreparedIssueGoal(context.Context, []byte, admission.IssueGoalSourceVerifier) (runintent.Intent, bool, error)
}

// GoalServiceFactory MUST create a fresh request-scoped service with trusted
// introspection and CatalogPolicy using the bearer token. Never cache the
// access token or accept identity from the submitted proposal.
type GoalServiceFactory func(context.Context, string) (GoalAdmitter, error)

// GoalStatusLookup is a separately configured, authenticated, read-only ACP
// authority lookup. The returned Intent is verified against all selectors
// before producing a receipt. A 404 is NOT proof of terminal non-existence.
type GoalStatusLookup func(context.Context, string, issuegoal.Prepared) (runintent.Intent, error)

type handler struct {
	factory GoalServiceFactory
	source  admission.IssueGoalSourceVerifier
	status  GoalStatusLookup
}

func configured(value any) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Func, reflect.Ptr, reflect.Interface, reflect.Slice, reflect.Map, reflect.Chan:
		return !v.IsNil()
	default:
		return true
	}
}

// NewHandler returns a standalone endpoint; it does not change ACP's default
// read-only HTTP server or implicitly enable public network admission.
func NewHandler(factory GoalServiceFactory, source admission.IssueGoalSourceVerifier) (http.Handler, error) {
	if !configured(factory) || !configured(source) {
		return nil, admission.ErrInvalidConfig
	}
	return &handler{factory: factory, source: source}, nil
}

// NewHandlerWithStatus enables a separate, non-mutating status endpoint only
// when the trusted host supplies an explicit request-scoped lookup.
func NewHandlerWithStatus(factory GoalServiceFactory, source admission.IssueGoalSourceVerifier, status GoalStatusLookup) (http.Handler, error) {
	if !configured(status) {
		return nil, admission.ErrInvalidConfig
	}
	base, err := NewHandler(factory, source)
	if err != nil {
		return nil, err
	}
	h := base.(*handler)
	h.status = status
	return h, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path != SubmitPath && (r.URL.Path != StatusPath || !configured(h.status)) {
		reject(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		reject(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if r.TLS == nil {
		reject(w, http.StatusUpgradeRequired, "tls_required")
		return
	}
	if r.URL.RawQuery != "" {
		reject(w, http.StatusBadRequest, "invalid_request")
		return
	}
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") || !validToken(strings.TrimPrefix(headers[0], "Bearer ")) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="acp-goal"`)
		reject(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		reject(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, issuegoal.MaxPreparedBytes+1))
	if err != nil {
		reject(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(data) > issuegoal.MaxPreparedBytes {
		reject(w, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	proposal, _, _, err := issuegoal.DecodePrepared(data)
	if err != nil {
		reject(w, http.StatusBadRequest, "invalid_goal")
		return
	}

	if r.URL.Path == StatusPath {
		h.serveStatus(w, r, strings.TrimPrefix(headers[0], "Bearer "), proposal)
		return
	}

	admitter, err := h.factory(r.Context(), strings.TrimPrefix(headers[0], "Bearer "))
	if err != nil {
		reject(w, classify(err), "admission_unavailable")
		return
	}
	if !configured(admitter) {
		reject(w, http.StatusServiceUnavailable, "admission_unavailable")
		return
	}
	intent, created, err := admitter.AdmitPreparedIssueGoal(r.Context(), data, h.source)
	if err != nil {
		reject(w, classify(err), "goal_not_admitted")
		return
	}
	// A downstream response is not a trustworthy acceptance receipt unless
	// the whole immutable target scope and RunIntent state are valid. Do not
	// expose a cross-project or malformed record merely because its digest matches.
	if err := intent.Validate(); err != nil ||
		intent.RequestDigest != proposal.RequestDigest ||
		intent.TenantID != proposal.Target.TenantID ||
		intent.ProjectID != proposal.Target.ProjectID ||
		intent.AgentID != proposal.Target.AgentID ||
		intent.ReleaseID != proposal.Target.ReleaseID ||
		intent.SessionID != proposal.Target.SessionID ||
		intent.IdempotencyKey != proposal.IdempotencyKey {
		reject(w, http.StatusServiceUnavailable, "invalid_admission_receipt")
		return
	}
	reply := struct {
		Schema        string `json:"schema"`
		RunIntentID   string `json:"run_intent_id"`
		RequestDigest string `json:"request_digest"`
		Status        string `json:"status"`
		Created       bool   `json:"created"`
	}{AcceptanceVersion, intent.ID, intent.RequestDigest, string(intent.Status), created}
	payload, err := json.Marshal(reply)
	if err != nil {
		reject(w, http.StatusServiceUnavailable, "admission_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_, _ = w.Write(payload)
	_, _ = w.Write([]byte("\n"))
}

// serveStatus never calls the write-admission service or public GitHub source.
func (h *handler) serveStatus(w http.ResponseWriter, r *http.Request, bearer string, proposal issuegoal.Prepared) {
	intent, err := h.status(r.Context(), bearer, proposal)
	if err != nil {
		switch {
		case errors.Is(err, admission.ErrUnauthenticated):
			reject(w, http.StatusUnauthorized, "unauthenticated")
		case errors.Is(err, admission.ErrPolicyDenied):
			reject(w, http.StatusForbidden, "policy_denied")
		case errors.Is(err, runpg.ErrNotFound):
			// Treat missing, mismatched, revoked and cross-scope records equally.
			// This response NEVER permits retry or final absence inference.
			reject(w, http.StatusNotFound, "not_found_or_denied")
		default:
			reject(w, http.StatusServiceUnavailable, "status_unavailable")
		}
		return
	}
	if err := intent.Validate(); err != nil ||
		intent.TenantID != proposal.Target.TenantID ||
		intent.ProjectID != proposal.Target.ProjectID ||
		intent.AgentID != proposal.Target.AgentID ||
		intent.ReleaseID != proposal.Target.ReleaseID ||
		intent.SessionID != proposal.Target.SessionID ||
		intent.IdempotencyKey != proposal.IdempotencyKey ||
		intent.RequestDigest != proposal.RequestDigest {
		reject(w, http.StatusServiceUnavailable, "invalid_status_receipt")
		return
	}
	reply := struct {
		Schema        string `json:"schema"`
		RunIntentID   string `json:"run_intent_id"`
		RequestDigest string `json:"request_digest"`
		Status        string `json:"status"`
	}{
		StatusVersion, intent.ID, intent.RequestDigest, string(intent.Status),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(reply)
}

func classify(err error) int {
	switch {
	case errors.Is(err, admission.ErrUnauthenticated):
		return http.StatusUnauthorized
	case errors.Is(err, admission.ErrPolicyDenied), errors.Is(err, admission.ErrIssueGoalSourceDenied):
		return http.StatusForbidden
	case errors.Is(err, runpg.ErrIdempotencyConflict):
		return http.StatusConflict
	case errors.Is(err, issuegoal.ErrInvalidGoal):
		return http.StatusBadRequest
	default:
		return http.StatusServiceUnavailable
	}
}
func validToken(token string) bool {
	if token == "" || len(token) > 8192 {
		return false
	}
	for _, c := range []byte(token) {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}
func reject(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Schema string `json:"schema"`
		Error  string `json:"error"`
	}{"acp.issue-goal-error/v1", code})
}
