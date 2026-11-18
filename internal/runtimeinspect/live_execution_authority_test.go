package runtimeinspect

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/authorityhttp"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

// This is a real TLS listener using the same actual OAuth-admitted and
// reconciled ACP Run, never a fake repository or caller tenant assertion.
func newLiveExecutionAuthorityReader(t *testing.T, repo *runpg.Repository, ref runpg.ExecutionAuthorityRef) func(int) {
	t.Helper()
	const peer = "spiffe://example.org/decision"
	roots, serverCert, clientCert := testSPIFFECertificatesFor(t, "spiffe://example.org/acp", peer)
	handler, err := authorityhttp.NewHandler(repo, peer, ref.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, Certificates: []tls.Certificate{serverCert},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCert},
	}}
	t.Cleanup(transport.CloseIdleConnections)
	h := &http.Client{Transport: transport}
	path := "/internal/v1/run-authority/" + ref.RunIntentID + "?" + url.Values{
		"run_id": {ref.RunID}, "request_digest": {ref.RequestDigest},
	}.Encode()
	call := func(client *http.Client, method, target string, want int) string {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Tenant-ID", "foreign")
		req.Header.Set("X-Forwarded-Client-Cert", peer)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(res.Body, 8193))
		if err != nil || res.StatusCode != want || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("live network authority expected %d, got %d: %v", want, res.StatusCode, err)
		}
		return string(raw)
	}
	call(h, http.MethodGet, path+"&tenant_id=foreign", http.StatusBadRequest)
	call(h, http.MethodPost, path, http.StatusMethodNotAllowed)
	call(h, http.MethodGet, strings.Replace(path, ref.RunID, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1), http.StatusForbidden)
	badHandler, err := authorityhttp.NewHandler(repo, "spiffe://example.org/other", ref.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	badServer := httptest.NewUnstartedServer(badHandler)
	badServer.TLS = srv.TLS.Clone()
	badServer.StartTLS()
	defer badServer.Close()
	badReq, err := http.NewRequest(http.MethodGet, badServer.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	badReq.Header.Set("X-Forwarded-Client-Cert", "spiffe://example.org/other")
	bad, err := h.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatal("real TLS wrong peer spoofed authority")
	}
	return func(want int) {
		t.Helper()
		body := call(h, http.MethodGet, path, want)
		if want != http.StatusOK {
			return
		}
		var wire map[string]any
		if json.Unmarshal([]byte(body), &wire) != nil || wire["schema_version"] != "acp.run-authority.v1" ||
			wire["tenant_id"] != ref.TenantID || wire["run_intent_id"] != ref.RunIntentID ||
			wire["run_id"] != ref.RunID || wire["request_digest"] != ref.RequestDigest ||
			wire["agent_id"] != "agent-1" || wire["session_id"] != "session-1" ||
			wire["agent_release_id"] != "release-1" || wire["policy_revision"] != "policy-revision-1" ||
			strings.Contains(body, "acp-ci-runner") || strings.Contains(body, "admission_issuer") ||
			strings.Contains(body, "execution_input") || strings.Contains(body, "permit") {
			t.Fatalf("invalid returned authority reference: %s", body)
		}
	}
}
