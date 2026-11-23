package admission

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The TLS IdP may return valid OAuth claims with conflicting HTTP
// representation metadata. ACP must fail closed before trusting a principal.
func TestIntrospectionRejectsDuplicateResponseContentTypeOverTLS(t *testing.T) {
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
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				clientID, secret, ok := r.BasicAuth()
				if r.Method != http.MethodPost || r.URL.Path != "/introspect" || !ok ||
					clientID != "acp-client" || secret != "fixture-secret" {
					t.Errorf("untrusted or malformed OAuth introspection request")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				for _, value := range tc.values {
					w.Header().Add("Content-Type", value)
				}
				_, _ = w.Write([]byte(validIntrospection()))
			}))
			defer server.Close()
			auth, err := NewIntrospector(IntrospectionConfig{
				Endpoint: server.URL + "/introspect", Issuer: testIssuer, Audience: testAudience,
				ClientID: "acp-client", ClientSecret: "fixture-secret", HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := auth.Authenticate(context.Background(), "opaque-test-token")
			if tc.deny {
				if !errors.Is(err, ErrIdentityUnavailable) || got != (Identity{}) {
					t.Fatalf("accepted ambiguous IdP HTTP headers as principal: identity=%+v err=%v", got, err)
				}
			} else if err != nil || got.Subject != "alice" || got.Issuer != testIssuer {
				t.Fatalf("rejected canonical TLS IdP response: identity=%+v err=%v", got, err)
			}
		})
	}
}
