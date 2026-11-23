package postfault

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
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func agentDEvidenceResponseFixture(t *testing.T, expected ExpectedAgentDWait,
	waitRaw, waitSig []byte, events []SignedAgentDInspect, head TrustedAgentDInspectHead,
	state string) AgentDEvidenceReadResponse {
	t.Helper()
	records := make([]AgentDEvidenceRecord, 0, len(events))
	for _, event := range events {
		records = append(records, AgentDEvidenceRecord{
			PayloadB64:   base64.StdEncoding.EncodeToString(event.Payload),
			SignatureB64: base64.StdEncoding.EncodeToString(event.Signature),
			Digest:       inspectSourceDigest(event.Payload),
		})
	}
	response := AgentDEvidenceReadResponse{
		Schema: AgentDEvidenceReadSchema, Ref: expected.Ref,
		State: state, NextAction: "HOLD", Head: head,
		Inspections: records, CanRetry: false,
	}
	if state == "EXITED" || state == "FAILED_CONFIRMED" {
		response.Terminal = &AgentDEvidenceRecord{
			PayloadB64:   base64.StdEncoding.EncodeToString(waitRaw),
			SignatureB64: base64.StdEncoding.EncodeToString(waitSig),
			Digest:       inspectSourceDigest(waitRaw),
		}
	}
	return response
}

func newAgentDEvidenceMTLSServer(t *testing.T, ref AgentDWaitRef, handler http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "agentd-evidence-test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  roots,
		MinVersion: tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerScope := "spiffe://agentd.test/tenant/" + url.PathEscape(ref.TenantID) +
		"/run/" + url.PathEscape(ref.RunID) + "/role/evidence-reader"
	peerURI, err := url.Parse(peerScope)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "agentd-evidence-reader"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		URIs:        []*url.URL{peerURI},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, clientKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCert := tls.Certificate{Certificate: [][]byte{clientDER, caDER}, PrivateKey: clientKey}
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
	t.Cleanup(transport.CloseIdleConnections)
	return server, &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func TestAgentDEvidenceClientFetchesAndVerifiesSameRunOverMutualTLS(t *testing.T) {
	b, keys, expected, waitRaw, waitSig, events, head, now, _ := g05SourceFixture(t)
	response := agentDEvidenceResponseFixture(t, expected, waitRaw, waitSig, events, head, "EXITED")
	server, client := newAgentDEvidenceMTLSServer(t, expected.Ref, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != AgentDEvidenceReadPath ||
			r.Header.Get("Content-Type") != "application/json" || r.TLS == nil ||
			len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 ||
			len(r.TLS.PeerCertificates[0].URIs) != 1 ||
			r.TLS.PeerCertificates[0].URIs[0].String() !=
				"spiffe://agentd.test/tenant/"+url.PathEscape(expected.Ref.TenantID)+
					"/run/"+url.PathEscape(expected.Ref.RunID)+"/role/evidence-reader" {
			t.Errorf("client did not use the exact mTLS read contract: method=%s path=%s peer=%v", r.Method, r.URL.Path, r.TLS != nil)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		var request AgentDEvidenceReadRequest
		if !StrictDecode(bytes.TrimSpace(raw), &request) || request.Ref != expected.Ref {
			t.Errorf("request did not carry the original immutable Ref: %q", raw)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		canonical, _ := json.Marshal(request)
		if !bytes.Equal(bytes.TrimSpace(raw), canonical) {
			t.Errorf("request JSON was not canonical: %q", raw)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	api := AgentDEvidenceClient{Endpoint: server.URL, HTTPClient: client}
	if err := api.Verify(context.Background(), b, keys, expected, head, now); err != nil {
		t.Fatalf("authentic source-signed mTLS response did not pass G05: %v", err)
	}
}

func TestAgentDEvidenceClientRejectsResponseIdentityAndHeadDrift(t *testing.T) {
	b, keys, expected, waitRaw, waitSig, events, head, now, _ := g05SourceFixture(t)
	_ = b
	_ = keys
	_ = now
	cases := []struct {
		name string
		edit func(*AgentDEvidenceReadResponse)
	}{
		{"foreign_run", func(r *AgentDEvidenceReadResponse) { r.Ref.RunID = "another-run" }},
		{"foreign_tenant", func(r *AgentDEvidenceReadResponse) { r.Ref.TenantID = "another-tenant" }},
		{"wrong_head", func(r *AgentDEvidenceReadResponse) { r.Head.Digest = "sha256:" + strings.Repeat("f", 64) }},
		{"retry_claim", func(r *AgentDEvidenceReadResponse) { r.CanRetry = true }},
		{"wrong_state", func(r *AgentDEvidenceReadResponse) { r.State = "FAILED_CONFIRMED" }},
		{"missing_terminal", func(r *AgentDEvidenceReadResponse) { r.Terminal = nil }},
		{"bad_source_digest", func(r *AgentDEvidenceReadResponse) { r.Inspections[0].Digest = "sha256:" + strings.Repeat("f", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := agentDEvidenceResponseFixture(t, expected, waitRaw, waitSig, events, head, "EXITED")
			tc.edit(&response)
			server, client := newAgentDEvidenceMTLSServer(t, expected.Ref, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			api := AgentDEvidenceClient{Endpoint: server.URL, HTTPClient: client}
			if _, err := api.Read(context.Background(), expected.Ref, head); err == nil {
				t.Fatal("client accepted a response with mismatched identity, Head or terminal contract")
			}
		})
	}
}

func TestAgentDEvidenceClientKeepsUnknownHoldUnresolved(t *testing.T) {
	b, keys, expected, waitRaw, waitSig, events, head, now, private := g05SourceFixture(t)
	var final AgentDInspectEvent
	if err := json.Unmarshal(events[1].Payload, &final); err != nil {
		t.Fatal(err)
	}
	final.State = "UNKNOWN"
	final.ExitReceiptDigest = ""
	events[1] = signedInspectSource(t, final, private)
	head.Digest = inspectSourceDigest(events[1].Payload)
	response := agentDEvidenceResponseFixture(t, expected, waitRaw, waitSig, events, head, "UNKNOWN")
	response.Terminal = nil
	server, client := newAgentDEvidenceMTLSServer(t, expected.Ref, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	api := AgentDEvidenceClient{Endpoint: server.URL, HTTPClient: client}
	if err := api.Verify(context.Background(), b, keys, expected, head, now); !errors.Is(err, ErrAgentDEvidenceUnresolved) {
		t.Fatalf("UNKNOWN/HOLD source response was not preserved as unresolved: %v", err)
	}
}

func TestAgentDEvidenceClientDoesNotFollowRedirects(t *testing.T) {
	_, _, expected, _, _, _, head, _, _ := g05SourceFixture(t)
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/redirected", http.StatusFound)
	}))
	defer redirect.Close()
	client := redirect.Client()
	api := AgentDEvidenceClient{Endpoint: redirect.URL, HTTPClient: client}
	_, err := api.Read(context.Background(), expected.Ref, head)
	if err == nil {
		t.Fatal("evidence client followed or accepted an HTTP redirect")
	}
}

func TestAgentDEvidenceClientExportsCanonicalLowercaseHeadKey(t *testing.T) {
	// The authoritative AgentD HTTP exporter declares json:"head" on its
	// EvidenceReadResponse. Uppercase "Head" changes canonical bytes, so
	// the ACP strict response re-marshaler would reject a legitimate source.
	raw, err := json.Marshal(AgentDEvidenceReadResponse{
		Schema: AgentDEvidenceReadSchema,
		Head: TrustedAgentDInspectHead{
			InspectCount: 1, JournalVersion: 1,
			Digest: "sha256:" + strings.Repeat("a", 64),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"head":`)) ||
		bytes.Contains(raw, []byte(`"Head":`)) {
		t.Fatalf("ACP canonical source export has incorrect head field spelling: %s", raw)
	}
}
