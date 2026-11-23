package authorityhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

// This probe deliberately denies even valid selector reads. The regression
// asserts that ambiguous representation metadata is rejected BEFORE any
// authenticated Guard read can reach the ACP authority data source.
type guardContentTypeReadProbe struct {
	reads int
}

func (p *guardContentTypeReadProbe) GetGuardRunAuthority(
	_ context.Context, _, _ string,
) (runpg.ExecutionAuthority, []byte, error) {
	p.reads++
	return runpg.ExecutionAuthority{}, nil, runpg.ErrCatalogDenied
}

func TestGuardReadEndpointsRejectDuplicateContentTypeBeforeAuthorityReadOverMTLS(t *testing.T) {
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(t.TempDir(), signingKey)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()

	peer := protectedTestPeer
	reader := &guardContentTypeReadProbe{}
	capability, err := NewGuardCapabilityHandler(reader, publisher, peer, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := NewGuardProtectedWorkspaceHandler(reader, publisher, peer, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(GuardCapabilityPath, capability)
	mux.Handle(GuardProtectedWorkspacePath, workspace)

	serverCert, clientCert, roots := testProtectedTLS(t, peer)
	server := httptest.NewUnstartedServer(mux)
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
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	runID := "11111111-1111-4111-8111-111111111111"
	requests := []struct {
		name string
		path string
		body any
	}{
		{
			name: "guard_capability", path: GuardCapabilityPath,
			body: GuardCapabilityRequest{
				SchemaVersion: GuardCapabilitySchema, RunID: runID,
				AgentID: "agent-1", AgentReleaseID: "release-1",
				SessionID: "session-1", CapabilityID: "sre.metrics.read",
				CapabilityVersion: "1.0.0", ResourceRef: "payments",
			},
		},
		{
			name: "guard_protected_workspace", path: GuardProtectedWorkspacePath,
			body: GuardProtectedWorkspaceRequest{
				SchemaVersion: GuardProtectedWorkspaceSchema, RunID: runID,
				AgentID: "agent-1", AgentReleaseID: "release-1",
				SessionID: "session-1", SubjectID: "subject-1",
				CapabilityID: "workspace.write", CapabilityVersion: "1.0.0",
				PolicyRevision: "policy-1", WorkspaceID: "workspace-1",
				ToolBindingDigest: strings.Repeat("a", 64), Audience: "audience-1",
			},
		},
	}
	headerCases := []struct {
		name   string
		values []string
		want   int
		read   bool
	}{
		{name: "canonical_one", values: []string{"application/json"}, want: http.StatusForbidden, read: true},
		{name: "same_value_repeated", values: []string{"application/json", "application/json"}, want: http.StatusBadRequest},
		{name: "conflicting_second_value", values: []string{"application/json", "text/plain"}, want: http.StatusBadRequest},
	}
	for _, endpoint := range requests {
		body, err := json.Marshal(endpoint.body)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range headerCases {
			t.Run(endpoint.name+"/"+tc.name, func(t *testing.T) {
				if tc.read {
					// An unambiguous request must still reach the genuine
					// read-only authority interface and get the denied result.
					if endpoint.name == "guard_capability" {
						if err := endpoint.body.(GuardCapabilityRequest).Validate(); err != nil {
							t.Fatal(err)
						}
					} else if err := endpoint.body.(GuardProtectedWorkspaceRequest).Validate(); err != nil {
						t.Fatal(err)
					}
				}
				req, err := http.NewRequest(http.MethodPost, server.URL+endpoint.path, bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				for _, value := range tc.values {
					req.Header.Add("Content-Type", value)
				}
				before := reader.reads
				response, err := client.Do(req)
				if err != nil {
					t.Fatalf("real TLS 1.3 Guard request failed: %v", err)
				}
				defer response.Body.Close()
				if response.StatusCode != tc.want {
					t.Fatalf("Guard accepted ambiguous Content-Type or blocked valid read: got HTTP %d, want %d", response.StatusCode, tc.want)
				}
				wantReads := before
				if tc.read {
					wantReads++
				}
				if reader.reads != wantReads {
					t.Fatalf("untrusted representation metadata reached authority reader: before=%d after=%d", before, reader.reads)
				}
			})
		}
	}
}
