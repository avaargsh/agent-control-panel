package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

func TestSubmitCLIHoldRecordIsDurableBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	holdPath := filepath.Join(t.TempDir(), "submit-hold.json")
	url, preparedJSON, tokenFile, caFile, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, err := os.ReadFile(holdPath)
		if err != nil {
			t.Errorf("POST occurred before hold record existed: %v", err)
		}
		var record map[string]any
		if json.Unmarshal(raw, &record) != nil ||
			record["schema"] != "acp.goal-submit-hold/v1" ||
			record["disposition"] != "UNKNOWN/HOLD" {
			t.Errorf("missing fail-closed hold record before POST: %s", string(raw))
		}
		if r.TLS == nil || r.Method != http.MethodPost {
			t.Errorf("unexpected GoalSubmit transport")
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "private-provider-response")
	}))
	defer done()
	var prepared issuegoal.Prepared
	if err := json.Unmarshal([]byte(preparedJSON), &prepared); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	err := run([]string{"submit", "--file", "-", "--url", url, "--token-file", tokenFile,
		"--ca-file", caFile, "--hold-record", holdPath}, strings.NewReader(preparedJSON), &out, &diagnostics)
	if err == nil || !strings.Contains(err.Error(), "outcome unknown") ||
		out.Len() != 0 || calls.Load() != 1 {
		t.Fatalf("lost ACK must remain UNKNOWN with one POST: err=%v output=%q requests=%d", err, out.String(), calls.Load())
	}
	raw, err := os.ReadFile(holdPath)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record["request_digest"] != prepared.RequestDigest ||
		record["idempotency_key"] != prepared.IdempotencyKey {
		t.Fatalf("hold record does not identify immutable request: %+v", record)
	}
	target, ok := record["target"].(map[string]any)
	if !ok || target["tenant_id"] != prepared.Target.TenantID ||
		target["project_id"] != prepared.Target.ProjectID {
		t.Fatal("hold record lost tenant/project identity")
	}
	info, err := os.Stat(holdPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("hold file must be 0600: info=%v err=%v", info, err)
	}
	for _, secret := range []string{"opaque-test-token", "private-provider-response", prepared.ExecutionInputBase64} {
		if strings.Contains(string(raw), secret) || strings.Contains(diagnostics.String(), secret) {
			t.Fatal("hold record or diagnostic leaked bearer, provider reply or full goal input")
		}
	}
}

func TestSubmitCLIHoldRecordFailsClosedBeforeNetwork(t *testing.T) {
	for _, tc := range []struct {
		name string
		path func(*testing.T) string
	}{
		{"existing-file", func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "existing.json")
			if err := os.WriteFile(path, []byte("DO NOT REPLACE"), 0600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"symlink", func(t *testing.T) string {
			dir := t.TempDir()
			dest := filepath.Join(dir, "target.json")
			if err := os.WriteFile(dest, []byte("DO NOT REPLACE"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "symlink.json")
			if err := os.Symlink(dest, path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"missing-parent", func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "missing", "hold.json")
		}},
		{"world-readable-parent", func(t *testing.T) string {
			dir := filepath.Join(t.TempDir(), "shared")
			if err := os.Mkdir(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0755); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "hold.json")
		}},
		{"relative-path", func(t *testing.T) string { return "relative-hold.json" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			url, proposal, tokenFile, caFile, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusCreated)
			}))
			defer done()
			path := tc.path(t)
			var out, diag bytes.Buffer
			err := run([]string{"submit", "--file", "-", "--url", url, "--token-file", tokenFile,
				"--ca-file", caFile, "--hold-record", path}, strings.NewReader(proposal), &out, &diag)
			if err == nil || calls.Load() != 0 || out.Len() != 0 {
				t.Fatalf("unsafe hold path allowed POST: err=%v requests=%d", err, calls.Load())
			}
			if tc.name == "existing-file" {
				raw, err := os.ReadFile(path)
				if err != nil || string(raw) != "DO NOT REPLACE" {
					t.Fatal("existing hold record was overwritten")
				}
			}
		})
	}
}

func TestSubmitCLIHoldRecordRemainsAsAttemptEvidenceOnSuccess(t *testing.T) {
	holdPath := filepath.Join(t.TempDir(), "submit-hold.json")
	url, proposal, tokenFile, caFile, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var prepared issuegoal.Prepared
		if err := json.NewDecoder(r.Body).Decode(&prepared); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, "{\"schema\":\"acp.issue-goal-acceptance/v1\",\"run_intent_id\":\"00000000-0000-4000-8000-000000000001\",\"request_digest\":%q,\"status\":\"PENDING\",\"created\":true}", prepared.RequestDigest)
	}))
	defer done()
	var out, diagnostic bytes.Buffer
	if err := run([]string{"submit", "--file", "-", "--url", url, "--token-file", tokenFile,
		"--ca-file", caFile, "--hold-record", holdPath}, strings.NewReader(proposal), &out, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		t.Fatal("verified admission receipt was lost")
	}
	if _, err := os.Stat(holdPath); err != nil {
		t.Fatal("durable attempt evidence must not disappear after success")
	}
}
