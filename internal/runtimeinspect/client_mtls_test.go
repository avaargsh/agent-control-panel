package runtimeinspect

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testSPIFFECertificates(t *testing.T) (*x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caParsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caParsed)

	issue := func(serial int64, identity string, server bool) tls.Certificate {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		uri, err := url.Parse(identity)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			URIs:         []*url.URL{uri},
		}
		if server {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, caParsed, public, caPrivate)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: private}
	}
	return roots, issue(2, "spiffe://example.org/runtime", true), issue(3, "spiffe://example.org/acp", false)
}

func TestInspectPerformsVerifiedMutualTLSAndNeverForwardsUserBearer(t *testing.T) {
	roots, serverCert, acpCert := testSPIFFECertificates(t)
	var accepted atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accepted.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" ||
			r.Header.Get("X-Forwarded-User") != "" || r.TLS == nil ||
			len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 ||
			len(r.TLS.PeerCertificates[0].URIs) != 1 ||
			r.TLS.PeerCertificates[0].URIs[0].String() != "spiffe://example.org/acp" ||
			r.URL.Path != inspectPath+testIntent ||
			r.URL.Query().Get("tenant_id") != testTenant ||
			r.URL.Query().Get("request_digest") != testDigest {
			http.Error(w, "unexpected authenticated request", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(
			`{"status":"FOUND","tenant_id":"tenant-1","run_intent_id":"` + testIntent + `","request_digest":"` + testDigest + `","run_id":"` + testRunID + `","workflow_id":"agent-run/v1/` + testRunID + `","created":false}`,
		))
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		Certificates: []tls.Certificate{serverCert},
	}
	srv.StartTLS()
	defer srv.Close()

	client, err := NewClient(srv.URL, "spiffe://example.org/runtime", roots, acpCert)
	if err != nil {
		t.Fatal(err)
	}
	scope := InspectRequest{TenantID: testTenant, RunIntentID: testIntent, RequestDigest: testDigest}
	found, err := client.Inspect(context.Background(), scope)
	if err != nil || found.Status != Found || found.RunID != testRunID || accepted.Load() != 1 {
		t.Fatalf("authenticated Runtime inspect: %+v err=%v handler_calls=%d", found, err, accepted.Load())
	}

	wrongPeer, err := NewClient(srv.URL, "spiffe://example.org/wrong-runtime", roots, acpCert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongPeer.Inspect(context.Background(), scope); err == nil {
		t.Fatal("wrong Runtime SPIFFE peer identity accepted")
	}
	if accepted.Load() != 1 {
		t.Fatal("wrong peer identity reached application handler")
	}
}

func TestInspectRejectsTLS12Downgrade(t *testing.T) {
	roots, serverCert, acpCert := testSPIFFECertificates(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ABSENT_UNCERTAIN"}`))
	}))
	srv.TLS = &tls.Config{
		MaxVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		Certificates: []tls.Certificate{serverCert},
	}
	srv.StartTLS()
	defer srv.Close()

	client, err := NewClient(srv.URL, "spiffe://example.org/runtime", roots, acpCert)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Inspect(context.Background(), InspectRequest{
		TenantID: testTenant, RunIntentID: testIntent, RequestDigest: testDigest,
	})
	if err == nil || !strings.Contains(err.Error(), "Runtime Inspect unavailable") {
		t.Fatalf("TLS 1.2 downgrade was accepted or misclassified: %v", err)
	}
}
