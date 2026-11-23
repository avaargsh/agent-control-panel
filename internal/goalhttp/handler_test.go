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
)

type fakeAdmitter struct {
	calls   int
	err     error
	created bool
	result  runintent.Intent
}

func (f *fakeAdmitter) AdmitPreparedIssueGoal(_ context.Context, _ []byte, _ admission.IssueGoalSourceVerifier) (runintent.Intent, bool, error) {
	f.calls++
	return f.result, f.created, f.err
}

type noopSource struct{}

func (*noopSource) VerifyIssueGoal(context.Context, admission.Target, issuegoal.Input) error {
	return nil
}

func validProposal(t *testing.T) []byte {
	t.Helper()
	raw := []byte(`{"schema_version":"acp.issue-goal/v1","target":{"tenant_id":"tenant-a","project_id":"project-a","agent_id":"coding","release_id":"release-v1","session_id":"session-1"},"idempotency_key":"issue-1","issue_url":"https://github.com/example/repository/issues/1","issue_snapshot_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","target_branch":"main","experiment_baseline_sha":"1111111111111111111111111111111111111111","integration_baseline_sha":"2222222222222222222222222222222222222222","acceptance_rules_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","budget":{"max_tokens":1000,"max_runtime_seconds":600,"max_sandbox_seconds":300}}`)
	proposal, err := issuegoal.Prepare(raw)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func request(body []byte, token string, tlsEnabled bool) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://acp.example/api/v1/goals:submit", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.TLS = nil
	if tlsEnabled {
		r.TLS = &tls.ConnectionState{}
	}
	return r
}
func TestSubmitRequiresTLSAndBearerAndStrictInputBeforeFactory(t *testing.T) {
	p := validProposal(t)
	svc := &fakeAdmitter{}
	calls := 0
	handler, err := NewHandler(func(_ context.Context, _ string) (GoalAdmitter, error) { calls++; return svc, nil }, &noopSource{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		r    *http.Request
		want int
	}{
		{"cleartext", request(p, "opaque", false), http.StatusUpgradeRequired},
		{"no bearer", request(p, "", true), http.StatusUnauthorized},
		{"malformed", request([]byte(`{"bad":true}`), "opaque", true), http.StatusBadRequest},
		{"over size", request(bytes.Repeat([]byte("a"), issuegoal.MaxPreparedBytes+1), "opaque", true), http.StatusRequestEntityTooLarge},
		{"bad media", request(p, "opaque", true), http.StatusUnsupportedMediaType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "bad media" {
				tc.r.Header.Set("Content-Type", "text/plain")
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, tc.r)
			if w.Code != tc.want {
				t.Fatalf("%s: got %d expected %d", w.Body.String(), w.Code, tc.want)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("sensitive response cacheable")
			}
		})
	}
	if calls != 0 || svc.calls != 0 {
		t.Fatalf("unsafe input reached auth or persistence: %d %d", calls, svc.calls)
	}
}
func TestSubmitCreatesOnlyPendingIntentAndReportsIdempotentReplay(t *testing.T) {
	p := validProposal(t)
	var prepared issuegoal.Prepared
	if err := json.Unmarshal(p, &prepared); err != nil {
		t.Fatal(err)
	}
	svc := &fakeAdmitter{created: true, result: runintent.Intent{
		ID: "run-intent-1", TenantID: "tenant-a", PrincipalID: "principal-a", ProjectID: "project-a",
		AgentID: "coding", ReleaseID: "release-v1", SessionID: "session-1", IdempotencyKey: "issue-1",
		RequestDigest: prepared.RequestDigest, Version: 1, Status: runintent.Pending,
	}}
	calls := 0
	handler, err := NewHandler(func(_ context.Context, token string) (GoalAdmitter, error) {
		calls++
		if token != "opaque-token" {
			t.Fatal("wrong bearer")
		}
		return svc, nil
	}, &noopSource{})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{http.StatusCreated, http.StatusOK} {
		if i == 1 {
			svc.created = false
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, request(p, "opaque-token", true))
		if w.Code != want {
			t.Fatalf("%s: got %d expected %d", w.Body.String(), w.Code, want)
		}
		if strings.Contains(w.Body.String(), "principal") || strings.Contains(w.Body.String(), "token") {
			t.Fatal("sensitive data exposed")
		}
		var reply map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		if reply["run_intent_id"] != "run-intent-1" || reply["request_digest"] != prepared.RequestDigest || reply["status"] != "PENDING" {
			t.Fatalf("bad reply: %#v", reply)
		}
	}
	if calls != 2 || svc.calls != 2 {
		t.Fatalf("expected 2 independently admitted requests: %d/%d", calls, svc.calls)
	}
}
func TestSubmitClassifiesDenialsWithoutLeakingErrors(t *testing.T) {
	p := validProposal(t)
	for _, tc := range []struct {
		err  error
		code int
	}{
		{admission.ErrIssueGoalSourceDenied, http.StatusForbidden},
		{admission.ErrIssueGoalSourceUnverified, http.StatusServiceUnavailable},
		{errors.New("database connection string with secret"), http.StatusServiceUnavailable},
	} {
		svc := &fakeAdmitter{err: tc.err}
		h, err := NewHandler(func(context.Context, string) (GoalAdmitter, error) { return svc, nil }, &noopSource{})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(p, "opaque", true))
		if w.Code != tc.code || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("unsafe rejection: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestSubmitRejectsUnboundOrMalformedAdmissionReceipt(t *testing.T) {
	p := validProposal(t)
	var prepared issuegoal.Prepared
	if err := json.Unmarshal(p, &prepared); err != nil {
		t.Fatal(err)
	}
	good := runintent.Intent{
		ID: "run-intent-1", TenantID: "tenant-a", PrincipalID: "principal-a", ProjectID: "project-a",
		AgentID: "coding", ReleaseID: "release-v1", SessionID: "session-1", IdempotencyKey: "issue-1",
		RequestDigest: prepared.RequestDigest, Version: 1, Status: runintent.Pending,
	}
	for _, tc := range []struct {
		name   string
		mutate func(*runintent.Intent)
	}{
		{"wrong_tenant", func(i *runintent.Intent) { i.TenantID = "tenant-b" }},
		{"wrong_project", func(i *runintent.Intent) { i.ProjectID = "project-b" }},
		{"wrong_agent", func(i *runintent.Intent) { i.AgentID = "other-agent" }},
		{"wrong_release", func(i *runintent.Intent) { i.ReleaseID = "other-release" }},
		{"wrong_session", func(i *runintent.Intent) { i.SessionID = "other-session" }},
		{"wrong_idempotency_key", func(i *runintent.Intent) { i.IdempotencyKey = "other-key" }},
		{"invalid_status", func(i *runintent.Intent) { i.Status = runintent.Status("COMPLETED") }},
		{"invalid_version", func(i *runintent.Intent) { i.Version = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent := good
			tc.mutate(&intent)
			svc := &fakeAdmitter{created: true, result: intent}
			h, err := NewHandler(func(context.Context, string) (GoalAdmitter, error) {
				return svc, nil
			}, &noopSource{})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(p, "opaque", true))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("invalid receipt %s was accepted: HTTP %d, body %s", tc.name, w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), intent.ID) {
				t.Fatalf("invalid receipt leaked RunIntent identifier: %s", w.Body.String())
			}
		})
	}
}
