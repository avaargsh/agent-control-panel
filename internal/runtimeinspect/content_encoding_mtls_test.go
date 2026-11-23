package runtimeinspect

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Authenticated Runtime receipt bytes must not be silently transformed by
// transparent HTTP decompression or an ambiguous encoding declaration.
func TestInspectRejectsCompressedOrAmbiguousContentEncodingOverMTLS(t *testing.T) {
	roots, serverCert, acpCert := testSPIFFECertificates(t)
	cases := []struct {
		name      string
		encodings []string
		compress  bool
		deny      bool
	}{
		{name: "plain_without_encoding"},
		{name: "explicit_single_identity", encodings: []string{"identity"}},
		{name: "gzip_auto_decompressed", encodings: []string{"gzip"}, compress: true, deny: true},
		{name: "duplicate_identity", encodings: []string{"identity", "identity"}, deny: true},
		{name: "unsupported_brotli", encodings: []string{"br"}, deny: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.URL.Path != inspectPath+testIntent {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				for _, encoding := range tc.encodings {
					w.Header().Add("Content-Encoding", encoding)
				}
				body := []byte(`{"status":"ABSENT_UNCERTAIN"}`)
				if tc.compress {
					var compressed bytes.Buffer
					writer := gzip.NewWriter(&compressed)
					_, _ = writer.Write(body)
					_ = writer.Close()
					body = compressed.Bytes()
				}
				_, _ = w.Write(body)
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
			got, err := client.Inspect(context.Background(), InspectRequest{
				TenantID: testTenant, RunIntentID: testIntent, RequestDigest: testDigest,
			})
			if tc.deny {
				if !errors.Is(err, ErrInvalidResponse) || got.Status != "" {
					t.Fatalf("unexpectedly accepted encoded or ambiguous Runtime receipt: status=%q err=%v", got.Status, err)
				}
				return
			}
			if err != nil || got.Status != AbsentUncertain {
				t.Fatalf("rejected ordinary identity-encoded Runtime receipt: status=%q err=%v", got.Status, err)
			}
		})
	}
}
