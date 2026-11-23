package admission

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The IdP is TLS-authenticated, but its response must not be transparently
// transformed or have ambiguous representation metadata before ACP treats the
// token claims as an authenticated principal.
func TestIntrospectionRejectsCompressedOrAmbiguousResponseEncodingOverTLS(t *testing.T) {
	cases := []struct {
		name      string
		encodings []string
		gzipBody  bool
		deny      bool
	}{
		{name: "plain_json"},
		{name: "single_identity", encodings: []string{"identity"}},
		{name: "gzip_auto_decompressed", encodings: []string{"gzip"}, gzipBody: true, deny: true},
		{name: "duplicate_identity", encodings: []string{"identity", "identity"}, deny: true},
		{name: "unsupported_brotli", encodings: []string{"br"}, deny: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				clientID, secret, ok := r.BasicAuth()
				if !ok || clientID != "acp-client" || secret != "fixture-secret" ||
					r.Method != http.MethodPost || r.URL.Path != "/introspect" {
					t.Error("introspection transport did not authenticate caller")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				for _, encoding := range tc.encodings {
					w.Header().Add("Content-Encoding", encoding)
				}
				payload := []byte(validIntrospection())
				if tc.gzipBody {
					var compressed bytes.Buffer
					writer := gzip.NewWriter(&compressed)
					_, _ = writer.Write(payload)
					_ = writer.Close()
					payload = compressed.Bytes()
				}
				_, _ = w.Write(payload)
			}))
			defer server.Close()
			auth, err := NewIntrospector(IntrospectionConfig{
				Endpoint: server.URL + "/introspect", Issuer: testIssuer, Audience: testAudience,
				ClientID: "acp-client", ClientSecret: "fixture-secret", HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			identity, err := auth.Authenticate(context.Background(), "opaque-test-token")
			if tc.deny {
				if !errors.Is(err, ErrIdentityUnavailable) || identity != (Identity{}) {
					t.Fatalf("accepted ambiguously encoded IdP claims: identity=%+v err=%v", identity, err)
				}
				return
			}
			if err != nil || identity.Subject != "alice" || identity.Issuer != testIssuer {
				t.Fatalf("rejected ordinary TLS IdP identity: identity=%+v err=%v", identity, err)
			}
		})
	}
}
