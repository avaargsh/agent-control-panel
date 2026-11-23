package postfault

// This test suite was ported from Draft #114 onto the canonical AgentD
// reader in Draft #112. No second wire parser, signer trust or verifier
// is permitted. The explicit TLS wrapper must reject wrong peer identity,
// insecure roots, replay, redirection and foreign Run evidence without
// weakening the canonical source-signed journal verifier.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type evidenceTestCA struct {
	root    *x509.Certificate
	private ed25519.PrivateKey
	raw     []byte
	pool    *x509.CertPool
}

func newEvidenceTestCA(t *testing.T) evidenceTestCA {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-only-evidence-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return evidenceTestCA{root: cert, private: key, raw: raw, pool: pool}
}

func (ca evidenceTestCA) certificate(t *testing.T, server bool, scope string) tls.Certificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<60))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	leaf := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "not-an-authority"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		if scope != "" {
			uri, err := url.Parse(scope)
			if err != nil {
				t.Fatal(err)
			}
			leaf.URIs = []*url.URL{uri}
		}
	} else {
		uri, err := url.Parse(scope)
		if err != nil {
			t.Fatal(err)
		}
		leaf.URIs = []*url.URL{uri}
	}
	raw, err := x509.CreateCertificate(rand.Reader, leaf, ca.root, key.Public(), ca.private)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{raw, ca.raw}, PrivateKey: key}
}

func newG05EvidenceTLSServer(t *testing.T, ca evidenceTestCA, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.certificate(t, true, "")},
		ClientCAs:    ca.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func agentDTestTLS(t *testing.T, ca evidenceTestCA, expected ExpectedAgentDWait) *tls.Config {
	t.Helper()
	scope := "spiffe://sandbox.test/tenant/" + expected.Ref.TenantID +
		"/run/" + expected.Ref.RunID + "/role/evidence-reader"
	return &tls.Config{
		RootCAs:      ca.pool,
		Certificates: []tls.Certificate{ca.certificate(t, false, scope)},
		MinVersion:   tls.VersionTLS13,
	}
}

func canonicalWireFixture(t *testing.T, expected ExpectedAgentDWait,
	waitRaw, waitSignature []byte, source []SignedAgentDInspect,
	head TrustedAgentDInspectHead) AgentDEvidenceReadResponse {
	t.Helper()
	wire := AgentDEvidenceReadResponse{
		Schema:     AgentDEvidenceReadSchema,
		Ref:        expected.Ref,
		State:      "EXITED",
		NextAction: "HOLD",
		Head: TrustedAgentDInspectHead{InspectCount: head.InspectCount,
			JournalVersion: head.JournalVersion, Digest: head.Digest},
		Inspections: make([]AgentDEvidenceRecord, 0, len(source)),
		Terminal: &AgentDEvidenceRecord{
			PayloadB64:   base64.StdEncoding.EncodeToString(waitRaw),
			SignatureB64: base64.StdEncoding.EncodeToString(waitSignature),
			Digest:       inspectSourceDigest(waitRaw),
		},
	}
	for _, signed := range source {
		wire.Inspections = append(wire.Inspections, AgentDEvidenceRecord{
			PayloadB64:   base64.StdEncoding.EncodeToString(signed.Payload),
			SignatureB64: base64.StdEncoding.EncodeToString(signed.Signature),
			Digest:       inspectSourceDigest(signed.Payload),
		})
	}
	return wire
}

func sourceTestHandler(t *testing.T, wire AgentDEvidenceReadResponse, status int) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 ||
			len(r.TLS.PeerCertificates) == 0 || r.Method != http.MethodPost ||
			r.URL.Path != AgentDEvidenceReadPath {
			http.Error(w, "untrusted client", http.StatusForbidden)
			return
		}
		var req struct {
			Ref AgentDWaitRef `json:"ref"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Ref != wire.Ref {
			http.Error(w, "cross-run", http.StatusForbidden)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(wire)
	}
}

func TestG05MTLSConsumerVerifiesOriginalSourceEvidence(t *testing.T) {
	b, keys, expected, waitRaw, waitSig, events, head, now, _ := g05SourceFixture(t)
	ca := newEvidenceTestCA(t)
	wire := canonicalWireFixture(t, expected, waitRaw, waitSig, events, head)
	server := newG05EvidenceTLSServer(t, ca, sourceTestHandler(t, wire, http.StatusOK))
	if err := FetchAndVerifyAgentDEvidence(context.Background(),
		server.URL+AgentDEvidenceReadPath, agentDTestTLS(t, ca, expected),
		b, keys, expected, head, now); err != nil {
		t.Fatalf("genuine mTLS scoped AgentD source evidence should verify: %v", err)
	}
}

func TestG05MTLSConsumerRejectsReboundWireAndUnresolvedSource(t *testing.T) {
	for _, name := range []string{
		"wrong_run", "wrong_attempt", "unsigned_inspect", "wrong_terminal_digest",
		"missing_terminal", "missing_chain", "prefix_rollback",
		"stale_trusted_head", "signed_unknown", "retriable", "wrong_schema",
		"missing_no_store", "error_status",
	} {
		t.Run(name, func(t *testing.T) {
			b, keys, expected, waitRaw, waitSig, events, head, now, _ := g05SourceFixture(t)
			wire := canonicalWireFixture(t, expected, waitRaw, waitSig, events, head)
			status := http.StatusOK
			switch name {
			case "wrong_run":
				wire.Ref.RunID = "different-run"
			case "wrong_attempt":
				wire.Ref.AttemptID = "different-attempt"
			case "unsigned_inspect":
				wire.Inspections[1].SignatureB64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			case "wrong_terminal_digest":
				wire.Terminal.Digest = "sha256:" + string(bytes.Repeat([]byte("f"), 64))
			case "missing_terminal":
				wire.Terminal = nil
			case "missing_chain":
				wire.Inspections = nil
			case "prefix_rollback":
				wire.Inspections = wire.Inspections[:1]
			case "stale_trusted_head":
				head.InspectCount++
			case "signed_unknown":
				wire.State = "UNKNOWN"
				wire.Terminal = nil
			case "retriable":
				wire.CanRetry = true
			case "wrong_schema":
				wire.Schema = "acp.untrusted/v1"
			case "error_status":
				status = http.StatusServiceUnavailable
			}
			ca := newEvidenceTestCA(t)
			handler := sourceTestHandler(t, wire, status)
			if name == "missing_no_store" {
				handler = func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(wire)
				}
			}
			server := newG05EvidenceTLSServer(t, ca, handler)
			err := FetchAndVerifyAgentDEvidence(context.Background(),
				server.URL+AgentDEvidenceReadPath, agentDTestTLS(t, ca, expected),
				b, keys, expected, head, now)
			if err == nil {
				t.Fatalf("trusted G05 consumer accepted bad source %s", name)
			}
		})
	}
}

func TestG05MTLSConsumerRejectsInsecureTransportAndTLSIdentityFailures(t *testing.T) {
	b, keys, expected, waitRaw, waitSig, events, head, now, _ := g05SourceFixture(t)
	ca := newEvidenceTestCA(t)
	server := newG05EvidenceTLSServer(t, ca,
		sourceTestHandler(t, canonicalWireFixture(t, expected, waitRaw, waitSig, events, head), http.StatusOK))
	for _, tc := range []struct {
		name     string
		endpoint string
		mutate   func(*tls.Config)
	}{
		{"plain_http", "http://127.0.0.1:1234" + AgentDEvidenceReadPath, nil},
		{"no_client_certificate", server.URL + AgentDEvidenceReadPath, func(c *tls.Config) { c.Certificates = nil }},
		{"no_roots", server.URL + AgentDEvidenceReadPath, func(c *tls.Config) { c.RootCAs = nil }},
		{"unsafe_skip_verify", server.URL + AgentDEvidenceReadPath, func(c *tls.Config) { c.InsecureSkipVerify = true }},
		{"wrong_client_identity", server.URL + AgentDEvidenceReadPath, func(c *tls.Config) {
			c.Certificates = []tls.Certificate{ca.certificate(t, false,
				"spiffe://sandbox.test/tenant/other/run/"+expected.Ref.RunID+"/role/evidence-reader")}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := agentDTestTLS(t, ca, expected)
			if tc.mutate != nil {
				tc.mutate(config)
			}
			if err := FetchAndVerifyAgentDEvidence(context.Background(), tc.endpoint,
				config, b, keys, expected, head, now); err == nil {
				t.Fatal("G05 accepted insecure or misbound TLS caller")
			}
		})
	}
}

func TestG05MTLSConsumerDoesNotFollowRedirectToUntrustedEndpoint(t *testing.T) {
	b, keys, expected, _, _, _, head, now, _ := g05SourceFixture(t)
	ca := newEvidenceTestCA(t)
	visited := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visited = true
		http.Error(w, "wrong service", http.StatusOK)
	}))
	t.Cleanup(target.Close)
	server := newG05EvidenceTLSServer(t, ca, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	if err := FetchAndVerifyAgentDEvidence(context.Background(),
		server.URL+AgentDEvidenceReadPath, agentDTestTLS(t, ca, expected),
		b, keys, expected, head, now); err == nil || visited {
		t.Fatalf("G05 followed untrusted redirect or accepted response: error=%v visited=%v", err, visited)
	}
}

func TestG05MTLSConsumerRejectsSameCARogueServerIdentityBeforeSendingRunEvidence(t *testing.T) {
	b, keys, expected, waitRaw, waitSig, events, head, now, _ := g05SourceFixture(t)
	ca := newEvidenceTestCA(t)
	wire := canonicalWireFixture(t, expected, waitRaw, waitSig, events, head)
	for _, tc := range []struct {
		name   string
		server string
	}{
		{"missing_agentd_uri", ""},
		{"wrong_same_ca_service", "spiffe://sandbox.test/role/unrelated-api"},
		{"foreign_trust_domain", "spiffe://foreign.test/role/agentd-evidence-server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewUnstartedServer(sourceTestHandler(t, wire, http.StatusOK))
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				sourceTestHandler(t, wire, http.StatusOK)(w, r)
			})
			server.TLS = &tls.Config{
				Certificates: []tls.Certificate{ca.certificate(t, true, tc.server)},
				ClientCAs:    ca.pool, ClientAuth: tls.RequireAndVerifyClientCert,
				MinVersion: tls.VersionTLS13,
			}
			server.StartTLS()
			defer server.Close()
			err := FetchAndVerifyAgentDEvidence(context.Background(),
				server.URL+AgentDEvidenceReadPath, agentDTestTLS(t, ca, expected),
				b, keys, expected, head, now)
			if err == nil || requests != 0 {
				t.Fatalf("same-CA wrong-server identity received original Run/Permit source request: err=%v requests=%d", err, requests)
			}
		})
	}
}
