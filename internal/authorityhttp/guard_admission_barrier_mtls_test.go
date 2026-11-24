package authorityhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/authoritycutover"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

type guardBarrierReader struct {
	authority runpg.ExecutionAuthority
	input     []byte
	events    *barrierEventLog
}

func (r *guardBarrierReader) GetGuardRunAuthority(_ context.Context, tenant, run string) (runpg.ExecutionAuthority, []byte, error) {
	r.events.add("read")
	if tenant != r.authority.Ref.TenantID || run != r.authority.Ref.RunID {
		return runpg.ExecutionAuthority{}, nil, runpg.ErrCatalogDenied
	}
	return r.authority, append([]byte(nil), r.input...), nil
}

func newGuardBarrierFixture(t *testing.T, path string) (Snapshot, []byte, *Publisher, []byte) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	var a Snapshot
	var input, raw, requestBody []byte
	if path == GuardProtectedWorkspacePath {
		var q GuardProtectedWorkspaceRequest
		a, input, raw, q = protectedFixture(t, now)
		requestBody, _ = json.Marshal(q)
	} else {
		input = []byte("{\"objective\":\"sre_incident_triage\",\"service\":\"payments\",\"signal\":\"latency\"}")
		config := ReleaseConfig{
			SchemaVersion: "acp.release-publication.v1",
			TenantID:      "tenant-1", ProjectID: "project-1",
			AgentID: "agent-1", AgentReleaseID: "release-1",
			PolicyRevision: "policy-1", CatalogVersion: "1.0.0",
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute),
			Services: []string{"payments"},
			Capabilities: []CapabilityContract{{
				ID: "sre.metrics.read", Version: "1.0.0",
				InputSchema:  json.RawMessage("{\"type\":\"object\",\"required\":[\"service\"]}"),
				OutputSchema: json.RawMessage("{\"type\":\"object\",\"required\":[\"series\"]}"),
				EffectClass:  "read_only", Idempotency: "safe", TenantScoped: true,
			}},
		}
		var err error
		raw, err = json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		a = Snapshot{
			SchemaVersion: "acp.run-authority.v1", TenantID: "tenant-1",
			RunIntentID:   "11111111-1111-4111-8111-111111111111",
			RunID:         "22222222-2222-4222-8222-222222222222",
			RequestDigest: "sha256:" + sha256Hex(input),
			ProjectID:     "project-1", AgentID: "agent-1", AgentReleaseID: "release-1",
			SessionID: "session-1", PrincipalID: "principal-1",
			SubjectID: "subject-1", ActorID: "subject-1", PolicyRevision: "policy-1",
			ConfigDigest: "sha256:" + sha256Hex(raw),
		}
		q := GuardCapabilityRequest{
			SchemaVersion: GuardCapabilitySchema, RunID: a.RunID,
			AgentID: a.AgentID, AgentReleaseID: a.AgentReleaseID,
			SessionID: a.SessionID, CapabilityID: "sre.metrics.read",
			CapabilityVersion: "1.0.0", ResourceRef: "payments",
		}
		requestBody, err = json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, strings.TrimPrefix(a.ConfigDigest, "sha256:")+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(dir, signer)
	if err != nil {
		t.Fatal(err)
	}
	return a, input, publisher, requestBody
}

func TestGuardOnlyHandlersHoldAdmissionBarrierThroughFlush(t *testing.T) {
	for _, endpoint := range []struct {
		name  string
		path  string
		build func(GuardCapabilityReader, *Publisher, func(context.Context) error, authoritycutover.RequestGate) (http.Handler, error)
	}{
		{
			name: "capability",
			path: GuardCapabilityPath,
			build: func(reader GuardCapabilityReader, publisher *Publisher, guard func(context.Context) error, gate authoritycutover.RequestGate) (http.Handler, error) {
				return NewBarrierGuardCapabilityHandler(reader, publisher, protectedTestPeer, "tenant-1", guard, gate)
			},
		},
		{
			name: "protected_workspace",
			path: GuardProtectedWorkspacePath,
			build: func(reader GuardCapabilityReader, publisher *Publisher, guard func(context.Context) error, gate authoritycutover.RequestGate) (http.Handler, error) {
				return NewBarrierGuardProtectedWorkspaceHandler(reader, publisher, protectedTestPeer, "tenant-1", guard, gate)
			},
		},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, scenario := range []struct {
				name             string
				gateFails        bool
				secondGuardFails bool
				wantStatus       int
				wantEvents       string
			}{
				{name: "valid", wantStatus: http.StatusOK, wantEvents: "acquire,guard,read,guard,flush,release"},
				{name: "closed_admission", gateFails: true, wantStatus: http.StatusServiceUnavailable, wantEvents: "acquire"},
				{name: "role_drift_after_read", secondGuardFails: true, wantStatus: http.StatusServiceUnavailable, wantEvents: "acquire,guard,read,guard,flush,release"},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					a, input, publisher, requestBody := newGuardBarrierFixture(t, endpoint.path)
					defer publisher.Close()
					events := &barrierEventLog{}
					reader := &guardBarrierReader{
						authority: executionAuthorityFromSnapshot(a), input: input, events: events,
					}
					gate := &barrierGateProbe{events: events, fail: scenario.gateFails}
					var guardCalls atomic.Int32
					readGuard := func(context.Context) error {
						events.add("guard")
						if scenario.secondGuardFails && guardCalls.Add(1) == 2 {
							return errors.New("authority role revoked after catalog read")
						}
					if !scenario.secondGuardFails {
						guardCalls.Add(1)
					}
					return nil
				}
					handler, err := endpoint.build(reader, publisher, readGuard, gate)
					if err != nil {
						t.Fatal(err)
					}
					serverCert, clientCert, roots := testProtectedTLS(t, protectedTestPeer)
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						handler.ServeHTTP(&admissionBarrierFlushWriter{ResponseWriter: w, events: events}, r)
					}))
					server.TLS = &tls.Config{
						MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
						ClientCAs: roots, Certificates: []tls.Certificate{serverCert},
					}
					server.StartTLS()
					defer server.Close()
					transport := &http.Transport{TLSClientConfig: &tls.Config{
						MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCert},
					}}
					defer transport.CloseIdleConnections()
					client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
					req, err := http.NewRequest(http.MethodPost, server.URL+endpoint.path, bytes.NewReader(requestBody))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Content-Type", "application/json")
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer resp.Body.Close()
					wire, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != scenario.wantStatus {
						t.Fatalf("unexpected status: got=%d want=%d body=%s", resp.StatusCode, scenario.wantStatus, wire)
					}
					if got := strings.Join(events.snapshot(), ","); got != scenario.wantEvents {
						t.Fatalf("unexpected admission/read/flush order: got=%q want=%q", got, scenario.wantEvents)
					}
					if scenario.wantStatus == http.StatusOK {
						var receipt map[string]any
						if err := json.Unmarshal(wire, &receipt); err != nil {
							t.Fatal(err)
						}
						if receipt["status"] != "VERIFIED" {
							t.Fatalf("valid Guard observation missing VERIFIED receipt: %s", wire)
						}
					} else if bytes.Contains(wire, []byte("VERIFIED")) {
						t.Fatalf("failed admission/role check leaked a success receipt: %s", wire)
					}
				})
			}
		})
	}
}
