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
	AcceptanceVersion = "acp.issue-goal-acceptance/v1"
)

type GoalAdmitter interface {
	AdmitPreparedIssueGoal(context.Context, []byte, admission.IssueGoalSourceVerifier) (runintent.Intent, bool, error)
}

// GoalServiceFactory MUST create a fresh request-scoped service with trusted
// introspection and CatalogPolicy using the bearer token. Never cache the
// access token or accept identity from the submitted proposal.
type GoalServiceFactory func(context.Context, string) (GoalAdmitter, error)

type handler struct {
	factory GoalServiceFactory
	source  admission.IssueGoalSourceVerifier
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

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path != SubmitPath {
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
	if intent.ID == "" || intent.RequestDigest != proposal.RequestDigest || intent.TenantID != proposal.Target.TenantID || intent.Status == "" {
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
