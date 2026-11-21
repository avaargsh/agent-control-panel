package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

func submitFixture(t *testing.T, handler http.Handler) (url, proposal, tokenFile, caFile string, done func()) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	directory := t.TempDir()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("missing test server certificate")
	}
	caFile = filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	tokenFile = filepath.Join(directory, "bearer")
	if err := os.WriteFile(tokenFile, []byte("opaque-test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	prepared, err := issuegoal.Prepare([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	return srv.URL + "/api/v1/goals:submit", string(wire), tokenFile, caFile, srv.Close
}

func TestSubmitCLIOverTLSWithExactBoundReceipt(t *testing.T) {
	var observed atomic.Int32
	var proposal string
	url, preparedJSON, tokenFile, caFile, closeServer := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		created := observed.Add(1) == 1
		if r.TLS == nil || r.URL.Path != "/api/v1/goals:submit" || r.Method != http.MethodPost ||
			r.Header.Get("Authorization") != "Bearer opaque-test-token" ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected outbound admission request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, issuegoal.MaxPreparedBytes+1))
		if err != nil {
			t.Error(err)
		}
		if string(body) != proposal {
			t.Errorf("proposal payload was modified in transit")
		}
		var p issuegoal.Prepared
		if err := json.Unmarshal([]byte(proposal), &p); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if created {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema":         "acp.issue-goal-acceptance/v1",
			"run_intent_id":  "00000000-0000-4000-8000-000000000001",
			"request_digest": p.RequestDigest,
			"status":         "PENDING",
			"created":        created,
		})
	}))
	proposal = preparedJSON
	defer closeServer()
	for _, wantCreated := range []bool{true, false} {
		var out, diagnostics bytes.Buffer
		err := run([]string{"submit", "--file", "-", "--url", url, "--token-file", tokenFile, "--ca-file", caFile},
			strings.NewReader(proposal), &out, &diagnostics)
		if err != nil {
			t.Fatal(err)
		}
		var receipt map[string]any
		if err := json.Unmarshal(out.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		if receipt["created"] != wantCreated || receipt["status"] != "PENDING" ||
			receipt["run_intent_id"] != "00000000-0000-4000-8000-000000000001" {
			t.Fatalf("unexpected acceptance receipt: %s", out.String())
		}
		if strings.Contains(out.String(), "opaque-test-token") || strings.Contains(diagnostics.String(), "opaque-test-token") {
			t.Fatal("bearer leaked to CLI output")
		}
	}
	if got := observed.Load(); got != 2 {
		t.Fatalf("expected one submission per explicit invocation; got %d", got)
	}
}

func TestSubmitCLIRejectsUnsafeConfigBeforeSendingBearer(t *testing.T) {
	var observed atomic.Int32
	url, proposal, tokenFile, caFile, closeServer := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		observed.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer closeServer()
	for _, tc := range []struct {
		name, url, tokenFile, caFile, body string
	}{
		{"cleartext", strings.Replace(url, "https:", "http:", 1), tokenFile, caFile, proposal},
		{"foreign host", "https://example.com/api/v1/goals:submit", tokenFile, caFile, proposal},
		{"URL userinfo", "https://user:pass@127.0.0.1:443/api/v1/goals:submit", tokenFile, caFile, proposal},
		{"URL query", url + "?access_token=secret", tokenFile, caFile, proposal},
		{"URL fragment", url + "#fragment", tokenFile, caFile, proposal},
		{"wrong path", strings.Replace(url, "/api/v1/goals:submit", "/health", 1), tokenFile, caFile, proposal},
		{"bad proposal", url, tokenFile, caFile, `{"schema":"wrong"}`},
		{"missing token file", url, "/missing/secret", caFile, proposal},
		{"missing CA file", url, tokenFile, "/missing/ca", proposal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			err := run([]string{"submit", "--file", "-", "--url", tc.url, "--token-file", tc.tokenFile, "--ca-file", tc.caFile},
				strings.NewReader(tc.body), &out, &diagnostic)
			if err == nil || out.Len() != 0 {
				t.Fatalf("unsafe invocation admitted: %v / %s", err, out.String())
			}
			if strings.Contains(fmt.Sprint(err), "opaque-test-token") {
				t.Fatal("bearer leaked in error")
			}
		})
	}
	if observed.Load() != 0 {
		t.Fatalf("unsafe CLI inputs hit the network %d times", observed.Load())
	}
	if err := os.Chmod(tokenFile, 0644); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	if err := run([]string{"submit", "--file", "-", "--url", url, "--token-file", tokenFile, "--ca-file", caFile},
		strings.NewReader(proposal), &out, &diagnostic); err == nil || out.Len() != 0 || observed.Load() != 0 {
		t.Fatal("world-readable token file was accepted")
	}
}

func TestSubmitCLIRejectsInvalidHTTPSResponseWithoutPrintingBody(t *testing.T) {
	cases := []struct {
		status int
		body   string
		media  string
	}{
		{http.StatusUnauthorized, `{"error":"secret-from-provider"}`, "application/json"},
		{http.StatusFound, "secret-from-redirect", "text/plain"},
		{http.StatusCreated, `{"schema":"acp.issue-goal-acceptance/v1","run_intent_id":"id","request_digest":"sha256:bad","status":"PENDING","created":true}`, "application/json"},
		{http.StatusCreated, strings.Repeat("A", 16*1024), "application/json"},
		{http.StatusCreated, `{"schema":"acp.issue-goal-acceptance/v1"}`, "application/json"},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			url, proposal, tokenFile, caFile, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.media)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer done()
			var out, diagnostic bytes.Buffer
			err := run([]string{"submit", "--file", "-", "--url", url, "--token-file", tokenFile, "--ca-file", caFile},
				strings.NewReader(proposal), &out, &diagnostic)
			if err == nil || out.Len() != 0 || strings.Contains(fmt.Sprint(err), "secret-from-") {
				t.Fatalf("unsafe remote reply was accepted or leaked: err=%v out=%s", err, out.String())
			}
		})
	}
}

func TestSubmitCLIRequiresTrustedTLS(t *testing.T) {
	url, proposal, tokenFile, caFile, done := submitFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("untrusted TLS request reached server handler")
	}))
	defer done()
	// httptest.NewTLSServer uses a shared test certificate on some Go
	// versions; generate an unrelated self-signed CA instead.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(71),
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	if err := run([]string{"submit", "--file", "-", "--url", url, "--token-file", tokenFile, "--ca-file", caFile},
		strings.NewReader(proposal), &out, &diagnostic); err == nil || out.Len() != 0 {
		t.Fatal("untrusted TLS certificate accepted")
	}
}
