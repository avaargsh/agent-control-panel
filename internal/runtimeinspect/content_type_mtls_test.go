package runtimeinspect

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The Runtime identity and JSON bytes can both be valid while its HTTP
// representation headers remain ambiguous. The ACP reader must fail closed
// before interpreting the response as authoritative Run identity or absence.
func TestInspectRejectsDuplicateResponseContentTypeOverMTLS(t *testing.T) {
	roots, serverCert, acpCert := testSPIFFECertificates(t)
	cases := []struct {
		name   string
		values []string
		deny   bool
	}{
		{name: "canonical_single_json", values: []string{"application/json"}},
		{name: "repeated_identical_json", values: []string{"application/json", "application/json"}, deny: true},
		{name: "conflicting_second_type", values: []string{"application/json", "text/plain"}, deny: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.URL.Path != inspectPath+testIntent {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				for _, value := range tc.values {
					w.Header().Add("Content-Type", value)
				}
				_, _ = w.Write([]byte(`{"status":"ABSENT_UNCERTAIN"}`))
			}))
			srv.TLS = &tls.Config{
				MinVersion: tls.VersionTLS13,
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs: roots,
				Certificates: []tls.Certificate{serverCert},
			}
			srv.StartTLS()
			defer srv.Close()

			client, err := NewClient(srv.URL, "spiffe://example.org/runtime", roots, acpCert)
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.Inspect(context.Background(), InspectRequest{
				TenantID: testTenant, RunIntentID: testIntent, RequestDigest: testDigest,
			})
			if tc.deny {
				if !errors.Is(err, ErrInvalidResponse) || got.Status != "" {
					t.Fatalf("ambiguous Runtime response header accepted: status=%q err=%v", got.Status, err)
				}
				return
			}
			if err != nil || got.Status != AbsentUncertain {
				t.Fatalf("valid single JSON response rejected: status=%q err=%v", got.Status, err)
			}
		})
	}
}
