package authorityhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type panicFlushResponseWriter struct {
	http.ResponseWriter
}

func (w panicFlushResponseWriter) Flush() {
	panic("synthetic response flush panic")
}

func TestBarrierGuardedHandlerReleasesLeaseWhenFlushPanics(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a, _, _, _ := protectedFixture(t, now)
	_, clientCert, _ := testProtectedTLS(t, protectedTestPeer)
	state := &tls.ConnectionState{
		HandshakeComplete: true,
		Version:           tls.VersionTLS13,
		PeerCertificates:  []*x509.Certificate{clientCert.Leaf},
		VerifiedChains:    [][]*x509.Certificate{{clientCert.Leaf}},
	}
	reader := &barrierHTTPReader{authority: executionAuthorityFromSnapshot(a)}
	var flushed atomic.Bool
	lease := &barrierHTTPLease{flushed: &flushed}
	gate := &barrierHTTPGate{lease: lease}
	handler, err := NewBarrierGuardedHandler(
		reader, protectedTestPeer, a.TenantID,
		func(context.Context) error { return nil }, gate,
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(
		http.MethodGet,
		PathPrefix+a.RunIntentID+"?run_id="+a.RunID+"&request_digest="+a.RequestDigest,
		nil,
	)
	req.TLS = state
	recorder := httptest.NewRecorder()

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		handler.ServeHTTP(panicFlushResponseWriter{ResponseWriter: recorder}, req)
	}()
	if recovered == nil {
		t.Fatal("synthetic response flush did not panic")
	}
	if gate.calls.Load() != 1 || reader.calls.Load() != 1 {
		t.Fatalf("request did not acquire and read exactly once: gate=%d reader=%d",
			gate.calls.Load(), reader.calls.Load())
	}
	if lease.releases.Load() != 1 {
		t.Fatalf("admission lease leaked after Flush panic: releases=%d", lease.releases.Load())
	}
	if lease.sawFlush.Load() || flushed.Load() {
		t.Fatal("panic writer unexpectedly reported a successful flush")
	}
}
