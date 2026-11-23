package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/postfault"
)

func TestPostfaultCLIUsesAuthenticatedAgentDServerIdentityBeforeAnyRunRead(t *testing.T) {
	// Both honest and wrong-service servers are signed by the SAME CA and
	// valid for the HTTPS hostname. Only the server's independent service
	// identity should distinguish them, during TLS handshake before HTTP.
	_, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(900), Subject: pkix.Name{CommonName: "test-only-g05-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPrivate.Public(), caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(scope string, server bool) tls.Certificate {
		t.Helper()
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<60))
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{
			SerialNumber: serial, Subject: pkix.Name{CommonName: "not-authorization"},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature,
		}
		if server {
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		if scope != "" {
			uri, err := url.Parse(scope)
			if err != nil {
				t.Fatal(err)
			}
			leaf.URIs = []*url.URL{uri}
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), caPrivate)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}
	}
	ref := postfault.AgentDWaitRef{
		TenantID: "tenant-a", RunID: "run-a", RuntimeAttemptID: "attempt-run-a",
		SandboxUID: "sandbox-a", CommandID: "command-a", AttemptID: "attempt-command-a",
		ProviderCommandUID: "provider-a", RequestDigest: "sha256:" + strings.Repeat("a", 64),
		GuardPermitID: "permit-a", PermitEpoch: 3, ProcessPID: 1234,
		ProcessStartTicks: 1000, HostBootID: "11111111-1111-1111-1111-111111111111",
	}
	expected := postfault.ExpectedAgentDWait{Ref: ref, GuardOperationID: "operation-a"}
	bundle := postfault.Bundle{Subject: postfault.Subject{
		TenantID: ref.TenantID, RunID: ref.RunID, GuardOperationID: expected.GuardOperationID,
	}}
	heads := postfault.TrustedAgentDInspectHead{
		InspectCount: 1, JournalVersion: 1, Digest: "sha256:" + strings.Repeat("b", 64),
	}
	keys := map[string]ed25519.PublicKey{"agentd": make(ed25519.PublicKey, ed25519.PublicKeySize)}
	credentials := &tls.Config{
		RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1",
		Certificates: []tls.Certificate{
			issue("spiffe://sandbox.test/tenant/tenant-a/run/run-a/role/evidence-reader", false),
		},
	}
	for _, tc := range []struct {
		name, serverScope string
		wantHTTP          bool
	}{
		{"same_ca_without_service_uri", "", false},
		{"same_ca_wrong_service_role", "spiffe://sandbox.test/role/other-service", false},
		{"same_ca_wrong_trust_domain", "spiffe://foreign.test/role/agentd-evidence-server", false},
		{"correct_server_service_uri", "spiffe://sandbox.test/role/agentd-evidence-server", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"invalid":"not-a-signed-source"}`))
			}))
			server.TLS = &tls.Config{
				Certificates: []tls.Certificate{issue(tc.serverScope, true)},
				ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: roots,
				MinVersion: tls.VersionTLS13,
			}
			server.StartTLS()
			defer server.Close()
			// The genuine source response is intentionally absent: this
			// focuses on trust-before-HTTP, not claiming recovery success.
			err := verifyBoundAgentDEvidence(context.Background(), server.URL,
				credentials, bundle, keys, expected, heads, now)
			n := requests.Load()
			if err == nil || (n == 1) != tc.wantHTTP {
				t.Fatalf("CLI AgentD TLS boundary failed: err=%v requests=%d wantHTTP=%v", err, n, tc.wantHTTP)
			}
		})
	}
}
