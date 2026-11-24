package authorityhttp

import (
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
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/authoritycutover"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

type barrierEventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *barrierEventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *barrierEventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type barrierGateProbe struct {
	events *barrierEventLog
	fail   bool
}

func (g *barrierGateProbe) Acquire(context.Context) (authoritycutover.RequestLease, error) {
	g.events.add("acquire")
	if g.fail {
		return nil, errors.New("cutover unavailable")
	}
	return &barrierGateLease{events: g.events}, nil
}

type barrierGateLease struct{ events *barrierEventLog }

func (l *barrierGateLease) Release() error {
	l.events.add("release")
	return nil
}

type barrierAuthorityReader struct {
	authority runpg.ExecutionAuthority
	input     []byte
	events    *barrierEventLog
}

func (r *barrierAuthorityReader) GetExecutionAuthority(_ context.Context, ref runpg.ExecutionAuthorityRef) (runpg.ExecutionAuthority, error) {
	r.events.add("read")
	if ref != r.authority.Ref {
		return runpg.ExecutionAuthority{}, runpg.ErrCatalogDenied
	}
	return r.authority, nil
}

func (r *barrierAuthorityReader) GetExecutionAuthorityInput(_ context.Context, ref runpg.ExecutionAuthorityRef) (runpg.ExecutionAuthority, []byte, error) {
	r.events.add("read")
	if ref != r.authority.Ref {
		return runpg.ExecutionAuthority{}, nil, runpg.ErrCatalogDenied
	}
	return r.authority, append([]byte(nil), r.input...), nil
}

type barrierFlushWriter struct {
	http.ResponseWriter
	events *barrierEventLog
}

func (w *barrierFlushWriter) Flush() {
	w.events.add("flush")
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func TestBarrierGuardedAuthorityAndPublicationHoldLeaseThroughResponseFlush(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	peer := "spiffe://example.org/ns/decision/sa/runtime"
	tenant := "tenant-barrier"
	input := []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
	config := ReleaseConfig{
		SchemaVersion: "acp.release-publication.v1", TenantID: tenant, ProjectID: "project-1",
		AgentID: "agent-1", AgentReleaseID: "release-1", PolicyRevision: "policy-1",
		CatalogVersion: "1.0.0", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute),
		Services: []string{"payments"},
		Capabilities: []CapabilityContract{{
			ID: "sre.metrics.read", Version: "1.0.0",
			InputSchema: json.RawMessage(`{"type":"object","required":["service"]}`),
			OutputSchema: json.RawMessage(`{"type":"object","required":["series"]}`),
			EffectClass: "read_only", Idempotency: "safe", TenantScoped: true,
		}},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Hex(raw)
	ref := runpg.ExecutionAuthorityRef{
		TenantID: tenant, RunIntentID: "11111111-1111-4111-8111-111111111111",
		RunID: "22222222-2222-4222-8222-222222222222", RequestDigest: "sha256:" + sha256Hex(input),
	}
	snapshot := runpg.ExecutionAuthority{
		Ref: ref, PrincipalID: "principal-1", AgentID: "agent-1",
		ReleaseID: "release-1", SessionID: "session-1",
		Snapshot: runintent.PrincipalSnapshot{
			Version: runintent.PrincipalSnapshotVersion, ProjectID: "project-1",
			SubjectID: "subject-1", ActorID: "subject-1", PolicyRevision: "policy-1",
			ConfigDigest: "sha256:" + digest,
		},
	}
	events := &barrierEventLog{}
	reader := &barrierAuthorityReader{authority: snapshot, input: input, events: events}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, digest+".json"), raw, 0600); err != nil {
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
	gate := &barrierGateProbe{events: events}
	handler, err := NewBarrierGuardedPublicationHandler(reader, publisher, peer, tenant,
		func(context.Context) error { return nil }, gate)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, clientCert, roots := testProtectedTLS(t, peer)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(&barrierFlushWriter{ResponseWriter: w, events: events}, r)
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
	send := func(path string, client *http.Client) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		if _, err := io.ReadAll(io.LimitReader(resp.Body, 8192)); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}
	query := "?run_id=" + ref.RunID + "&request_digest=" + ref.RequestDigest
	if status := send(PathPrefix+ref.RunIntentID+query, client); status != http.StatusOK {
		t.Fatalf("valid Run Authority positive control failed: %d", status)
	}
	if got := strings.Join(events.snapshot(), ","); got != "acquire,read,flush,release" {
		t.Fatalf("Run Authority lease did not cover read and response flush: %s", got)
	}
	events = &barrierEventLog{}
	gate.events, reader.events = events, events
	if status := send(PublicationPathPrefix+ref.RunIntentID+query, client); status != http.StatusOK {
		t.Fatalf("valid signed Decision Publication positive control failed: %d", status)
	}
	if got := strings.Join(events.snapshot(), ","); got != "acquire,read,flush,release" {
		t.Fatalf("Decision Publication lease did not cover read/sign/response flush: %s", got)
	}

	// Invalid syntax and failed mTLS must not acquire a database lease.
	events = &barrierEventLog{}
	gate.events, reader.events = events, events
	if status := send(PathPrefix+"not-a-uuid"+query, client); status != http.StatusBadRequest {
		t.Fatalf("invalid request status: %d", status)
	}
	if len(events.snapshot()) != 0 {
		t.Fatalf("invalid request touched admission gate: %v", events.snapshot())
	}
	noCertificate := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
	}}
	_ = send(PathPrefix+ref.RunIntentID+query, noCertificate)
	if len(events.snapshot()) != 0 {
		t.Fatalf("unauthenticated request touched admission gate: %v", events.snapshot())
	}
	noCertificate.Transport.(*http.Transport).CloseIdleConnections()

	// A closed/unavailable gate must fail closed before any catalog read or
	// signed publication is constructed.
	events = &barrierEventLog{}
	gate.events, reader.events, gate.fail = events, events, true
	if status := send(PublicationPathPrefix+ref.RunIntentID+query, client); status != http.StatusServiceUnavailable {
		t.Fatalf("closed cutover gate did not return 503: %d", status)
	}
	if got := strings.Join(events.snapshot(), ","); got != "acquire" {
		t.Fatalf("catalog read or publication occurred while gate was closed: %s", got)
	}
}
