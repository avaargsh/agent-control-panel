package goalhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/admission"
	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

func statusHTTPReq(body []byte, bearer string, secure bool) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://acp.example/api/v1/goals:status", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if secure {
		r.TLS = &tls.ConnectionState{}
	} else {
		r.TLS = nil
	}
	return r
}

func TestGoalStatusRequiresSecurePreparedInputBeforeLookup(t *testing.T) {
	raw := validProposal(t)
	calls := 0
	lookup := func(_ context.Context, _ string, _ issuegoal.Prepared) (runintent.Intent, error) {
		calls++
		return runintent.Intent{}, nil
	}
	h, err := NewHandlerWithStatus(func(context.Context, string) (GoalAdmitter, error) {
		t.Fatal("status attempted admission")
		return nil, nil
	}, &noopSource{}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		req  *http.Request
		code int
	}{
		{"cleartext", statusHTTPReq(raw, "secret", false), http.StatusUpgradeRequired},
		{"no-token", statusHTTPReq(raw, "", true), http.StatusUnauthorized},
		{"invalid-prepared", statusHTTPReq([]byte(`{"schema":"wrong"}`), "secret", true), http.StatusBadRequest},
		{"oversized", statusHTTPReq(bytes.Repeat([]byte("x"), issuegoal.MaxPreparedBytes+1), "secret", true), http.StatusRequestEntityTooLarge},
		{"wrong-media", statusHTTPReq(raw, "secret", true), http.StatusUnsupportedMediaType},
		{"query-leak", statusHTTPReq(raw, "secret", true), http.StatusBadRequest},
		{"get-not-allowed", statusHTTPReq(raw, "secret", true), http.StatusMethodNotAllowed},
	}
	tests[4].req.Header.Set("Content-Type", "text/plain")
	tests[5].req.URL.RawQuery = "idempotency_key=secret"
	tests[6].req.Method = http.MethodGet
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, tc.req)
			if w.Code != tc.code || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("invalid requests reached status authority %d times", calls)
	}
}

func TestGoalStatusReturnsOnlyBoundRunIntentAndNeverGrantsRetry(t *testing.T) {
	raw := validProposal(t)
	var p issuegoal.Prepared
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	good := runintent.Intent{
		ID: "intent-1", TenantID: p.Target.TenantID, ProjectID: p.Target.ProjectID,
		AgentID: p.Target.AgentID, ReleaseID: p.Target.ReleaseID,
		SessionID: p.Target.SessionID, PrincipalID: "internal-principal",
		IdempotencyKey: p.IdempotencyKey, RequestDigest: p.RequestDigest,
		Status: runintent.Pending, Version: 1,
	}
	var calls int
	var lookupErr error
	result := good
	h, err := NewHandlerWithStatus(func(context.Context, string) (GoalAdmitter, error) {
		t.Fatal("status must not invoke submit")
		return nil, nil
	}, &noopSource{}, func(_ context.Context, token string, req issuegoal.Prepared) (runintent.Intent, error) {
		calls++
		if token != "private-bearer" || req.RequestDigest != good.RequestDigest {
			t.Fatal("identity or request selector changed")
		}
		return result, lookupErr
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, statusHTTPReq(raw, "private-bearer", true))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var receipt map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["schema"] != "acp.issue-goal-status/v1" || receipt["run_intent_id"] != good.ID ||
		receipt["request_digest"] != good.RequestDigest || receipt["status"] != "PENDING" ||
		receipt["retry_allowed"] != nil || strings.Contains(w.Body.String(), good.PrincipalID) ||
		strings.Contains(w.Body.String(), "private-bearer") {
		t.Fatalf("unsafe read receipt: %v", receipt)
	}
	lookupErr = runpg.ErrNotFound
	w = httptest.NewRecorder()
	h.ServeHTTP(w, statusHTTPReq(raw, "private-bearer", true))
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "not_found_or_denied") {
		t.Fatalf("missing or denied must be ambiguous: %d %s", w.Code, w.Body.String())
	}
	lookupErr = errors.New("db credential secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, statusHTTPReq(raw, "private-bearer", true))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "credential") {
		t.Fatalf("database error escaped: %d %s", w.Code, w.Body.String())
	}
	lookupErr = nil
	result = good
	result.TenantID = "tenant-b"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, statusHTTPReq(raw, "private-bearer", true))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), good.ID) {
		t.Fatalf("cross-tenant record escaped: %d %s", w.Code, w.Body.String())
	}
	if calls != 4 {
		t.Fatalf("unexpected status lookups: %d", calls)
	}
}

func TestStatusHandlerCannotBeEnabledWithoutLookup(t *testing.T) {
	_, err := NewHandlerWithStatus(func(context.Context, string) (GoalAdmitter, error) { return nil, nil }, &noopSource{}, nil)
	if !errors.Is(err, admission.ErrInvalidConfig) {
		t.Fatal("empty status authority accepted")
	}
}
