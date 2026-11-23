package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

// A local attempt marker is evidence of what the operator originally sent,
// never proof of ACP admission or Runtime execution.
func goalHoldFixture(t *testing.T, preparedJSON string) (string, issuegoal.Prepared) {
	t.Helper()
	var p issuegoal.Prepared
	if err := json.Unmarshal([]byte(preparedJSON), &p); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateHoldDirectory(t), "attempt.json")
	if err := persistGoalHoldRecord(path, p); err != nil {
		t.Fatal(err)
	}
	return path, p
}

func TestGoalStatusCLIRequiresMatchingDurableHoldRecordBeforeAnyNetwork(t *testing.T) {
	var requests atomic.Int32
	url, preparedJSON, token, ca, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/api/v1/goals:status" || r.Method != http.MethodPost {
			t.Errorf("status attempted a non-read-only endpoint")
		}
		var p issuegoal.Prepared
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"schema": "acp.issue-goal-status/v1", "run_intent_id": "original-intent",
			"request_digest": p.RequestDigest, "status": "PENDING",
		})
	}))
	defer done()
	url = strings.Replace(url, "/api/v1/goals:submit", "/api/v1/goals:status", 1)
	recordPath, _ := goalHoldFixture(t, preparedJSON)
	var out, diag bytes.Buffer
	err := run([]string{"status", "--file", "-", "--url", url, "--token-file", token,
		"--ca-file", ca, "--hold-record", recordPath}, strings.NewReader(preparedJSON), &out, &diag)
	if err != nil || requests.Load() != 1 || !strings.Contains(out.String(), "original-intent") {
		t.Fatalf("valid local hold identity prevented read-only lookup: err=%v output=%s count=%d", err, out.String(), requests.Load())
	}
	if !strings.Contains(string(mustReadHold(t, recordPath)), "UNKNOWN/HOLD") {
		t.Fatal("read-only status must not rewrite or clear the immutable attempt marker")
	}
}

func mustReadHold(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestGoalStatusCLIRejectsUnboundOrUnsafeHoldWithoutNetwork(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"wrong-request-digest", func(t *testing.T, path string) { changeHoldJSON(t, path, "request_digest", "sha256:"+strings.Repeat("f", 64)) }},
		{"wrong-idempotency-key", func(t *testing.T, path string) { changeHoldJSON(t, path, "idempotency_key", "other-attempt") }},
		{"wrong-tenant", func(t *testing.T, path string) { changeHoldTarget(t, path, "tenant_id", "other-tenant") }},
		{"wrong-project", func(t *testing.T, path string) { changeHoldTarget(t, path, "project_id", "other-project") }},
		{"wrong-session", func(t *testing.T, path string) { changeHoldTarget(t, path, "session_id", "other-session") }},
		{"wrong-schema", func(t *testing.T, path string) { changeHoldJSON(t, path, "schema", "other-v1") }},
		{"fake-terminal-disposition", func(t *testing.T, path string) { changeHoldJSON(t, path, "disposition", "RETRY_ALLOWED") }},
		{"unrecognized-field", func(t *testing.T, path string) { changeHoldJSON(t, path, "operator_override", "allow") }},
		{"duplicate-key", func(t *testing.T, path string) {
			raw := mustReadHold(t, path)
			raw = bytes.TrimSuffix(raw, []byte{10})
			raw = append(raw[:len(raw)-1], []byte(`,"schema":"acp.goal-submit-hold/v1"}`)...)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized-record", func(t *testing.T, path string) {
			if err := os.WriteFile(path, bytes.Repeat([]byte("z"), 8192), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"world-readable-record", func(t *testing.T, path string) {
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"world-readable-parent", func(t *testing.T, path string) {
			if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink-record", func(t *testing.T, path string) {
			data := mustReadHold(t, path)
			if err := os.Remove(path); err != nil { t.Fatal(err) }
			target := filepath.Join(filepath.Dir(path), "target.json")
			if err := os.WriteFile(target, data, 0600); err != nil { t.Fatal(err) }
			if err := os.Symlink(target, path); err != nil { t.Fatal(err) }
		}},
		{"missing-record", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil { t.Fatal(err) }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			url, proposal, token, ca, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer done()
			url = strings.Replace(url, "/api/v1/goals:submit", "/api/v1/goals:status", 1)
			path, _ := goalHoldFixture(t, proposal)
			tc.mutate(t, path)
			var out, diag bytes.Buffer
			err := run([]string{"status", "--file", "-", "--url", url, "--token-file", token,
				"--ca-file", ca, "--hold-record", path}, strings.NewReader(proposal), &out, &diag)
			if err == nil || requests.Load() != 0 || out.Len() != 0 ||
				strings.Contains(err.Error(), "opaque-test-token") {
				t.Fatalf("untrusted local evidence contacted ACP: err=%v requests=%d out=%q", err, requests.Load(), out.String())
			}
		})
	}
}

func changeHoldJSON(t *testing.T, path, key string, value any) {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(mustReadHold(t, path), &obj); err != nil { t.Fatal(err) }
	obj[key] = value
	raw, err := json.Marshal(obj)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, raw, 0600); err != nil { t.Fatal(err) }
}

func changeHoldTarget(t *testing.T, path, key, value string) {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(mustReadHold(t, path), &obj); err != nil { t.Fatal(err) }
	target, ok := obj["target"].(map[string]any)
	if !ok { t.Fatal("missing target") }
	target[key] = value
	raw, err := json.Marshal(obj)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, raw, 0600); err != nil { t.Fatal(err) }
}

func TestGoalStatusCLIMatchingHoldStillPreservesUnknownOn404(t *testing.T) {
	var requests atomic.Int32
	url, proposal, token, ca, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "private upstream response")
	}))
	defer done()
	url = strings.Replace(url, "/api/v1/goals:submit", "/api/v1/goals:status", 1)
	path, _ := goalHoldFixture(t, proposal)
	var out, diag bytes.Buffer
	err := run([]string{"status", "--file", "-", "--url", url, "--token-file", token,
		"--ca-file", ca, "--hold-record", path}, strings.NewReader(proposal), &out, &diag)
	if err == nil || !strings.Contains(err.Error(), "UNKNOWN/HOLD") || requests.Load() != 1 ||
		out.Len() != 0 || strings.Contains(err.Error(), "private upstream") {
		t.Fatalf("ambiguous status granted replay: err=%v out=%q requests=%d", err, out.String(), requests.Load())
	}
}
