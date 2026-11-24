package authorityhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

type guardCancellationProbe struct {
	reader *protectedRunReaderFixture
	armed  atomic.Bool
	hits   atomic.Int32
}

type guardCancelContextKey struct{}

func (p *guardCancellationProbe) GetGuardRunAuthority(ctx context.Context, tenant, run string) (runpg.ExecutionAuthority, []byte, error) {
	current, input, err := p.reader.GetGuardRunAuthority(ctx, tenant, run)
	if err == nil && p.armed.Load() {
		p.hits.Add(1)
		ctx.Value(guardCancelContextKey{}).(context.CancelFunc)()
	}
	return current, input, err
}

func TestGuardReadEndpointsRejectCancelledSuccessfulAuthorityReadOverMTLS(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, workspace := range []bool{false, true} {
		name := "capability"
		if workspace {
			name = "protected_workspace"
		}
		t.Run(name, func(t *testing.T) {
			a, input, raw, workspaceRequest := protectedFixture(t, now)
			var request any = workspaceRequest
			path := GuardProtectedWorkspacePath
			if !workspace {
				config := ReleaseConfig{
					SchemaVersion: "acp.release-publication.v1", TenantID: a.TenantID,
					ProjectID: a.ProjectID, AgentID: a.AgentID, AgentReleaseID: a.AgentReleaseID,
					PolicyRevision: a.PolicyRevision, CatalogVersion: "1.0.0",
					IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute),
					Services: []string{"payments"},
					Capabilities: []CapabilityContract{{
						ID: "sre.metrics.read", Version: "1.0.0",
						InputSchema:  json.RawMessage(`{"type":"object","required":["service"]}`),
						OutputSchema: json.RawMessage(`{"type":"object","required":["series"]}`),
						EffectClass:  "read_only", Idempotency: "safe", TenantScoped: true,
					}},
				}
				var err error
				raw, err = json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
				request = GuardCapabilityRequest{
					SchemaVersion: GuardCapabilitySchema, RunID: a.RunID,
					AgentID: a.AgentID, AgentReleaseID: a.AgentReleaseID,
					SessionID: a.SessionID, CapabilityID: "sre.metrics.read",
					CapabilityVersion: "1.0.0", ResourceRef: "payments",
				}
				path = GuardCapabilityPath
			}
			a.ConfigDigest = "sha256:" + sha256Hex(raw)
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, sha256Hex(raw)+".json"), raw, 0600); err != nil {
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
			defer publisher.Close()
			probe := &guardCancellationProbe{reader: &protectedRunReaderFixture{authority: a, input: input}}
			var handler http.Handler
			if workspace {
				handler, err = NewGuardProtectedWorkspaceHandler(probe, publisher, protectedTestPeer, a.TenantID)
			} else {
				handler, err = NewGuardCapabilityHandler(probe, publisher, protectedTestPeer, a.TenantID)
			}
			if err != nil {
				t.Fatal(err)
			}
			serverCert, clientCert, roots := testProtectedTLS(t, protectedTestPeer)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				handler.ServeHTTP(w, r.WithContext(context.WithValue(ctx, guardCancelContextKey{}, cancel)))
			}))
			server.TLS = &tls.Config{
				MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs: roots, Certificates: []tls.Certificate{serverCert},
			}
			server.StartTLS()
			defer server.Close()
			transport := &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13, RootCAs: roots,
				Certificates: []tls.Certificate{clientCert},
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			send := func() (int, []byte) {
				t.Helper()
				req, err := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				wire, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
				if err != nil {
					t.Fatal(err)
				}
				return resp.StatusCode, wire
			}
			assertVerified := func() {
				t.Helper()
				status, wire := send()
				var receipt struct {
					Status string `json:"status"`
					RunID  string `json:"run_id"`
				}
				if status != http.StatusOK || json.Unmarshal(wire, &receipt) != nil ||
					receipt.Status != "VERIFIED" || receipt.RunID != a.RunID {
					t.Fatalf("valid original Run positive control failed: HTTP %d %s", status, wire)
				}
			}
			assertVerified()
			probe.armed.Store(true)
			status, wire := send()
			probe.armed.Store(false)
			if probe.hits.Load() != 1 {
				t.Fatalf("cancellation did not follow successful authority read: %d", probe.hits.Load())
			}
			var refused map[string]string
			if status != http.StatusServiceUnavailable || json.Unmarshal(wire, &refused) != nil ||
				len(refused) != 1 || refused["error"] != "AUTHORITY_UNAVAILABLE" {
				t.Errorf("cancelled Guard authority request must return only 503 AUTHORITY_UNAVAILABLE: HTTP %d %s", status, wire)
			}
			assertVerified()
		})
	}
}
