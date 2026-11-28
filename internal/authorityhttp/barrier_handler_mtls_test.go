package authorityhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/authoritycutover"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

type barrierHTTPReader struct {
	authority runpg.ExecutionAuthority
	input     []byte
	entered   chan struct{}
	resume    chan struct{}
	once      sync.Once
	calls     atomic.Int32
}

func (r *barrierHTTPReader) wait(ctx context.Context) error {
	r.calls.Add(1)
	if r.entered != nil {
		r.once.Do(func() { close(r.entered) })
	}
	if r.resume != nil {
		select {
		case <-r.resume:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (r *barrierHTTPReader) GetExecutionAuthority(ctx context.Context, ref runpg.ExecutionAuthorityRef) (runpg.ExecutionAuthority, error) {
	if err := r.wait(ctx); err != nil {
		return runpg.ExecutionAuthority{}, err
	}
	if ref != r.authority.Ref {
		return runpg.ExecutionAuthority{}, runpg.ErrCatalogDenied
	}
	return r.authority, nil
}

func (r *barrierHTTPReader) GetExecutionAuthorityInput(ctx context.Context, ref runpg.ExecutionAuthorityRef) (runpg.ExecutionAuthority, []byte, error) {
	if err := r.wait(ctx); err != nil {
		return runpg.ExecutionAuthority{}, nil, err
	}
	if ref != r.authority.Ref {
		return runpg.ExecutionAuthority{}, nil, runpg.ErrCatalogDenied
	}
	return r.authority, append([]byte(nil), r.input...), nil
}

type barrierHTTPLease struct {
	flushed  *atomic.Bool
	releases atomic.Int32
	sawFlush atomic.Bool
}

func (l *barrierHTTPLease) Release() error {
	l.sawFlush.Store(l.flushed.Load())
	l.releases.Add(1)
	return nil
}

type barrierHTTPGate struct {
	lease *barrierHTTPLease
	err   error
	calls atomic.Int32
}

func (g *barrierHTTPGate) Acquire(context.Context) (authoritycutover.RequestLease, error) {
	g.calls.Add(1)
	if g.err != nil {
		return nil, g.err
	}
	return g.lease, nil
}

type barrierFlushWriter struct {
	http.ResponseWriter
	flushed *atomic.Bool
}

func (w barrierFlushWriter) Flush() {
	w.flushed.Store(true)
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func newBarrierHTTPFixture(t *testing.T, now time.Time) (Snapshot, []byte, *Publisher) {
	t.Helper()
	a, _, _, _ := protectedFixture(t, now)
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
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
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
	return a, []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`), publisher
}

func executionAuthorityFromSnapshot(a Snapshot) runpg.ExecutionAuthority {
	return runpg.ExecutionAuthority{
		Ref: runpg.ExecutionAuthorityRef{
			TenantID: a.TenantID, RunIntentID: a.RunIntentID,
			RunID: a.RunID, RequestDigest: a.RequestDigest,
		},
		PrincipalID: a.PrincipalID, AgentID: a.AgentID,
		ReleaseID: a.AgentReleaseID, SessionID: a.SessionID,
		Snapshot: runintent.PrincipalSnapshot{
			Version: runintent.PrincipalSnapshotVersion, ProjectID: a.ProjectID,
			SubjectID: a.SubjectID, ActorID: a.ActorID,
			PolicyRevision: a.PolicyRevision, ConfigDigest: a.ConfigDigest,
		},
	}
}

func TestBarrierGuardedAuthorityAndPublicationHoldLeaseThroughFlush(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, endpoint := range []struct {
		name string
		path string
	}{
		{name: "run_authority", path: PathPrefix},
		{name: "decision_publication", path: PublicationPathPrefix},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			a, input, publisher := newBarrierHTTPFixture(t, now)
			defer publisher.Close()
			serverCert, clientCert, roots := testProtectedTLS(t, protectedTestPeer)
			transport := &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13, RootCAs: roots,
				Certificates: []tls.Certificate{clientCert},
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
			requestURL := fmt.Sprintf("%s%s?run_id=%s&request_digest=%s",
				endpoint.path, a.RunIntentID, a.RunID, a.RequestDigest)

			t.Run("lease held until final response flush", func(t *testing.T) {
				var flushed atomic.Bool
				lease := &barrierHTTPLease{flushed: &flushed}
				gate := &barrierHTTPGate{lease: lease}
				reader := &barrierHTTPReader{
					authority: executionAuthorityFromSnapshot(a), input: input,
					entered: make(chan struct{}), resume: make(chan struct{}),
				}
				var guardCalls atomic.Int32
				handler, err := NewBarrierGuardedPublicationHandler(
					reader, publisher, protectedTestPeer, a.TenantID,
					func(context.Context) error {
						if gate.calls.Load() != 1 {
							return errors.New("database role guard ran outside admission lease")
						}
						guardCalls.Add(1)
						return nil
					}, gate,
				)
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					handler.ServeHTTP(barrierFlushWriter{ResponseWriter: w, flushed: &flushed}, r)
				}))
				server.TLS = &tls.Config{
					MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
					ClientCAs: roots, Certificates: []tls.Certificate{serverCert},
				}
				server.StartTLS()
				defer server.Close()

				type response struct {
					status int
					body   []byte
					err    error
				}
				done := make(chan response, 1)
				go func() {
					req, err := http.NewRequest(http.MethodGet, server.URL+requestURL, nil)
					if err != nil {
						done <- response{err: err}
						return
					}
					resp, err := client.Do(req)
					if err != nil {
						done <- response{err: err}
						return
					}
					defer resp.Body.Close()
					body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
					done <- response{status: resp.StatusCode, body: body, err: err}
				}()

				select {
				case <-reader.entered:
				case <-time.After(3 * time.Second):
					t.Fatal("request never reached the authorized catalog read")
				}
				if lease.releases.Load() != 0 || flushed.Load() {
					t.Fatal("admission lease was released before the catalog read completed")
				}
				close(reader.resume)
				got := <-done
				if got.err != nil {
					t.Fatal(got.err)
				}
				if got.status != http.StatusOK || len(bytes.TrimSpace(got.body)) == 0 {
					t.Fatalf("valid mTLS authority request failed: HTTP %d %s", got.status, got.body)
				}
				if gate.calls.Load() != 1 || reader.calls.Load() != 1 || guardCalls.Load() != 2 {
					t.Fatalf("unexpected gate/read/guard counts: gate=%d reader=%d guard=%d",
						gate.calls.Load(), reader.calls.Load(), guardCalls.Load())
				}
				if lease.releases.Load() != 1 || !lease.sawFlush.Load() || !flushed.Load() {
					t.Fatalf("lease must release exactly once after response flush: releases=%d sawFlush=%v flushed=%v",
						lease.releases.Load(), lease.sawFlush.Load(), flushed.Load())
				}
			})

			t.Run("closed admission fails before catalog read", func(t *testing.T) {
				gate := &barrierHTTPGate{err: authoritycutover.ErrAdmissionClosed}
				reader := &barrierHTTPReader{authority: executionAuthorityFromSnapshot(a), input: input}
				var guardCalls atomic.Int32
				handler, err := NewBarrierGuardedPublicationHandler(
					reader, publisher, protectedTestPeer, a.TenantID,
					func(context.Context) error { guardCalls.Add(1); return nil }, gate,
				)
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewUnstartedServer(handler)
				server.TLS = &tls.Config{
					MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
					ClientCAs: roots, Certificates: []tls.Certificate{serverCert},
				}
				server.StartTLS()
				defer server.Close()
				req, err := http.NewRequest(http.MethodGet, server.URL+requestURL, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusServiceUnavailable {
					t.Fatalf("closed admission must fail closed: HTTP %d", resp.StatusCode)
				}
				if gate.calls.Load() != 1 || reader.calls.Load() != 0 || guardCalls.Load() != 0 {
					t.Fatalf("closed admission reached protected reader/guard: gate=%d reader=%d guard=%d",
						gate.calls.Load(), reader.calls.Load(), guardCalls.Load())
				}
			})
		})
	}
}
