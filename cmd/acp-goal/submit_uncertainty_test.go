package main

// Regression-only extraction from Draft PR #90, rebased independently on
// main after #86 provided the guarded GoalSubmit HTTP/CLI implementation.
// Incomplete or intermediary HTTP replies must not cause a blind retry.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

func TestSubmitCLIReportsUnknownForUnverifiableSuccessfulHTTPReply(t *testing.T) {
	// An HTTP 200/201 response can arrive after the server committed the
	// RunIntent, even when its acceptance receipt is truncated, malformed or
	// inconsistent. Do not treat an untrusted response as a confirmed refusal.
	cases := []struct {
		name             string
		status           int
		contentType      string
		cacheControl     string
		body             string
		truncateResponse bool
	}{
		{"created_missing_no_store", http.StatusCreated, "application/json", "", `{"schema":"acp.issue-goal-acceptance/v1"}`, false},
		{"created_wrong_media", http.StatusCreated, "text/plain", "no-store", "private-response-do-not-log", false},
		{"created_wrong_digest", http.StatusCreated, "application/json", "no-store",
			`{"schema":"acp.issue-goal-acceptance/v1","run_intent_id":"receipt-1","request_digest":"sha256:bad","status":"PENDING","created":true}`, false},
		{"created_partial_body", http.StatusCreated, "application/json", "no-store", `{"schema":"acp.issue-goal-acceptance/v1"`, true},
		{"replay_truncated", http.StatusOK, "application/json", "no-store", `{"run_intent_id":"receipt-1"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			url, proposal, tokenFile, caFile, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || r.Method != http.MethodPost ||
					r.Header.Get("Authorization") != "Bearer opaque-test-token" {
					t.Error("unverifiable receipt fixture received unsafe request")
					return
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, issuegoal.MaxPreparedBytes+1))
				requests.Add(1)
				w.Header().Set("Content-Type", tc.contentType)
				if tc.cacheControl != "" {
					w.Header().Set("Cache-Control", tc.cacheControl)
				}
				if tc.truncateResponse {
					w.Header().Set("Content-Length", fmt.Sprint(len(tc.body)+128))
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer done()
			var out, diagnostics bytes.Buffer
			err := run([]string{"submit", "--file", "-", "--url", url,
				"--token-file", tokenFile, "--ca-file", caFile},
				strings.NewReader(proposal), &out, &diagnostics)
			if err == nil || !strings.Contains(err.Error(), "outcome unknown") ||
				!strings.Contains(err.Error(), "inspect ACP before retrying") ||
				out.Len() != 0 || requests.Load() != 1 {
				t.Fatalf("unverifiable successful HTTP reply incorrectly accepted/retried: err=%v request-count=%d output-size=%d",
					err, requests.Load(), out.Len())
			}
			for _, secret := range []string{"opaque-test-token", "private-response-do-not-log", "sha256:bad"} {
				if strings.Contains(err.Error(), secret) || strings.Contains(diagnostics.String(), secret) {
					t.Fatal("untrusted reply or bearer leaked into diagnostics")
				}
			}
		})
	}
}

func TestSubmitCLIReportsUnknownForPotentiallyCommittedServerErrors(t *testing.T) {
	// A 5xx error may be emitted after the database transaction committed
	// (e.g. receipt validation after admission). HTTP 408 can also reflect
	// an ambiguous request boundary. Neither is proof of a rolled-back write.
	for _, status := range []int{
		http.StatusRequestTimeout,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var received atomic.Int32
			url, proposal, tokenFile, caFile, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, issuegoal.MaxPreparedBytes+1))
				received.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"error":"secret-from-upstream"}`)
			}))
			defer done()
			var out, diagnostics bytes.Buffer
			err := run([]string{"submit", "--file", "-", "--url", url,
				"--token-file", tokenFile, "--ca-file", caFile},
				strings.NewReader(proposal), &out, &diagnostics)
			if err == nil || !strings.Contains(err.Error(), "outcome unknown") ||
				!strings.Contains(err.Error(), "inspect ACP before retrying") ||
				out.Len() != 0 || received.Load() != 1 {
				t.Fatalf("ambiguous HTTP %d was treated as a confirmed failed write or retried: err=%v requests=%d output=%d", status, err, received.Load(), out.Len())
			}
			for _, secret := range []string{"opaque-test-token", "secret-from-upstream"} {
				if strings.Contains(err.Error(), secret) || strings.Contains(diagnostics.String(), secret) {
					t.Fatal("ambiguous server response leaked a secret")
				}
			}
		})
	}
}

func TestSubmitCLIKeepsDefinitiveHTTPClientDenialsDistinctFromUnknown(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			url, proposal, tokenFile, caFile, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "untrusted-response-secret")
			}))
			defer done()
			var out, diagnostics bytes.Buffer
			err := run([]string{"submit", "--file", "-", "--url", url,
				"--token-file", tokenFile, "--ca-file", caFile},
				strings.NewReader(proposal), &out, &diagnostics)
			if err == nil || strings.Contains(err.Error(), "outcome unknown") ||
				!strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", status)) ||
				out.Len() != 0 || calls.Load() != 1 {
				t.Fatalf("definitive HTTP %d denial was misclassified: err=%v requests=%d", status, err, calls.Load())
			}
			if strings.Contains(err.Error(), "untrusted-response-secret") ||
				strings.Contains(diagnostics.String(), "untrusted-response-secret") {
				t.Fatal("server denial body leaked into CLI")
			}
		})
	}
}

func TestSubmitCLIUnknownForNonDefinitiveHTTPStatuses(t *testing.T) {
	// An intermediary may answer after forwarding the POST. Neither a
	// redirect nor rate limiting proves that the RunIntent was not committed.
	// The CLI must not follow redirects, leak the reply or retry automatically.
	for _, status := range []int{
		http.StatusTemporaryRedirect,
		http.StatusUnprocessableEntity,
		http.StatusTooManyRequests,
	} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var received atomic.Int32
			url, proposal, tokenFile, caFile, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer opaque-test-token" {
					t.Error("unexpected request or missing authenticated bearer")
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, issuegoal.MaxPreparedBytes+1))
				received.Add(1)
				w.Header().Set("Location", "https://example.invalid/unsafe")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "private-upstream-response")
			}))
			defer done()
			var out, diagnostics bytes.Buffer
			err := run([]string{"submit", "--file", "-", "--url", url,
				"--token-file", tokenFile, "--ca-file", caFile},
				strings.NewReader(proposal), &out, &diagnostics)
			if err == nil || !strings.Contains(err.Error(), "outcome unknown") ||
				!strings.Contains(err.Error(), "inspect ACP before retrying") ||
				out.Len() != 0 || received.Load() != 1 {
				t.Fatalf("non-definitive HTTP %d was called a refusal, followed, or retried: err=%v requests=%d out=%d",
					status, err, received.Load(), out.Len())
			}
			for _, secret := range []string{"opaque-test-token", "private-upstream-response"} {
				if strings.Contains(err.Error(), secret) || strings.Contains(diagnostics.String(), secret) {
					t.Fatal("sensitive data leaked through uncertain outcome")
				}
			}
		})
	}
}
