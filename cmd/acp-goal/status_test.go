package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

func TestGoalStatusCLILooksUpOriginalWithoutResubmitting(t *testing.T) {
	var calls atomic.Int32
	var wire string
	url, proposal, token, ca, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/goals:status" ||
			r.Header.Get("Authorization") != "Bearer opaque-test-token" || r.TLS == nil {
			t.Errorf("status lookup crossed endpoint boundary")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, issuegoal.MaxPreparedBytes+1))
		if err != nil || string(body) != wire {
			t.Errorf("lookup changed the original prepared request")
		}
		var p issuegoal.Prepared
		if err := json.Unmarshal(body, &p); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema": "acp.issue-goal-status/v1", "run_intent_id": "original-intent-1",
			"request_digest": p.RequestDigest, "status": "PENDING",
		})
	}))
	defer done()
	wire = proposal
	url = strings.Replace(url, "/api/v1/goals:submit", "/api/v1/goals:status", 1)
	var out, diagnostics bytes.Buffer
	err := run([]string{"status", "--file", "-", "--url", url, "--token-file", token, "--ca-file", ca},
		strings.NewReader(proposal), &out, &diagnostics)
	if err != nil || calls.Load() != 1 || !strings.Contains(out.String(), "original-intent-1") ||
		strings.Contains(out.String(), "opaque-test-token") {
		t.Fatalf("authenticated read failed: err=%v output=%s calls=%d", err, out.String(), calls.Load())
	}
}

func TestGoalStatusCLI404IsNotAbsenceProofAndCannotAutoRetry(t *testing.T) {
	var calls atomic.Int32
	url, proposal, token, ca, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/v1/goals:status" {
			t.Errorf("query tried a different endpoint: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"not_found_or_denied","secret":"upstream-secret"}`)
	}))
	defer done()
	url = strings.Replace(url, "/api/v1/goals:submit", "/api/v1/goals:status", 1)
	var out, diagnostics bytes.Buffer
	err := run([]string{"status", "--file", "-", "--url", url, "--token-file", token, "--ca-file", ca},
		strings.NewReader(proposal), &out, &diagnostics)
	if err == nil || !strings.Contains(err.Error(), "UNKNOWN/HOLD") || calls.Load() != 1 ||
		out.Len() != 0 || strings.Contains(err.Error(), "upstream-secret") {
		t.Fatalf("missing intent wrongly treated as safe replay: err=%v calls=%d", err, calls.Load())
	}
}

func TestGoalStatusCLIDeniesUntrustedOrMismatchedReceipts(t *testing.T) {
	for _, body := range []string{
		`{"schema":"acp.issue-goal-status/v1","run_intent_id":"other","request_digest":"sha256:wrong","status":"PENDING"}`,
		`{"schema":"acp.issue-goal-status/v1","run_intent_id":"id","request_digest":"sha256:bad","status":"PENDING","status":"ACCEPTED"}`,
		`{"schema":"acp.issue-goal-status/v1","run_intent_id":"id","request_digest":"sha256:bad","status":"COMPLETED"}`,
	} {
		url, proposal, token, ca, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, body)
		}))
		url = strings.Replace(url, "/api/v1/goals:submit", "/api/v1/goals:status", 1)
		var out, diagnostic bytes.Buffer
		err := run([]string{"status", "--file", "-", "--url", url, "--token-file", token, "--ca-file", ca},
			strings.NewReader(proposal), &out, &diagnostic)
		done()
		if err == nil || out.Len() != 0 {
			t.Fatalf("unbound status receipt trusted: err=%v output=%s", err, out.String())
		}
	}
}
