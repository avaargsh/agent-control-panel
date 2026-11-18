package admission

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

const testIssuer = "https://identity.example.test/realms/acp"
const testAudience = "acp-control-plane"

func validIntrospection() string {
	return fmt.Sprintf(`{"active":true,"iss":%q,"aud":[%q],"sub":"alice","exp":%d,"token_type":"Bearer"}`, testIssuer, testAudience, time.Now().Add(time.Hour).Unix())
}

func introspectionFixture(t *testing.T, response string) *Introspector {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/introspect" {
			t.Error("unexpected introspection request")
		}
		id, secret, ok := r.BasicAuth()
		if !ok || id != "acp-client" || secret != "fixture-secret" {
			t.Error("missing authenticated introspection client")
		}
		if err := r.ParseForm(); err != nil || r.PostForm.Get("token") != "opaque-test-token" || r.PostForm.Get("token_type_hint") != "access_token" {
			t.Error("invalid introspection form")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)
	auth, err := NewIntrospector(IntrospectionConfig{
		Endpoint: server.URL + "/introspect", Issuer: testIssuer, Audience: testAudience,
		ClientID: "acp-client", ClientSecret: "fixture-secret", HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func TestIntrospectionRequiresActiveBoundUnexpiredPrincipal(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()
	for _, tc := range []struct {
		name string
		body string
		ok   bool
	}{
		{"valid", validIntrospection(), true},
		{"inactive", `{"active":false}`, false},
		{"wrong issuer", fmt.Sprintf(`{"active":true,"iss":"https://foreign.test","aud":%q,"sub":"alice","exp":%d}`, testAudience, future), false},
		{"wrong audience", fmt.Sprintf(`{"active":true,"iss":%q,"aud":"other","sub":"alice","exp":%d}`, testIssuer, future), false},
		{"expired", fmt.Sprintf(`{"active":true,"iss":%q,"aud":%q,"sub":"alice","exp":%d}`, testIssuer, testAudience, past), false},
		{"missing expiry", fmt.Sprintf(`{"active":true,"iss":%q,"aud":%q,"sub":"alice"}`, testIssuer, testAudience), false},
		{"future nbf", fmt.Sprintf(`{"active":true,"iss":%q,"aud":%q,"sub":"alice","exp":%d,"nbf":%d}`, testIssuer, testAudience, future, future), false},
		{"duplicate active", fmt.Sprintf(`{"active":false,"active":true,"iss":%q,"aud":%q,"sub":"alice","exp":%d}`, testIssuer, testAudience, future), false},
		{"missing subject", fmt.Sprintf(`{"active":true,"iss":%q,"aud":%q,"exp":%d}`, testIssuer, testAudience, future), false},
		{"string audience", fmt.Sprintf(`{"active":true,"iss":%q,"aud":%q,"sub":"alice","exp":%d}`, testIssuer, testAudience, future), true},
		{"refresh token", fmt.Sprintf(`{"active":true,"iss":%q,"aud":%q,"sub":"alice","exp":%d,"token_type":"refresh_token"}`, testIssuer, testAudience, future), false},
		{"trailing content", validIntrospection() + " {}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := introspectionFixture(t, tc.body)
			id, err := auth.Authenticate(context.Background(), "opaque-test-token")
			if tc.ok {
				if err != nil || id.Subject != "alice" || id.Issuer != testIssuer || !id.ExpiresAt.After(time.Now()) {
					t.Fatalf("expected verified identity, got %+v / %v", id, err)
				}
			} else if !errors.Is(err, ErrUnauthenticated) || id != (Identity{}) {
				t.Fatalf("invalid token accepted: %+v / %v", id, err)
			}
		})
	}
}

func TestIntrospectionDoesNotFollowRedirect(t *testing.T) {
	called := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	auth, err := NewIntrospector(IntrospectionConfig{
		Endpoint: source.URL, Issuer: testIssuer, Audience: testAudience,
		ClientID: "acp-client", ClientSecret: "fixture-secret", HTTPClient: source.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Authenticate(context.Background(), "opaque-test-token"); !errors.Is(err, ErrIdentityUnavailable) || called {
		t.Fatalf("redirect followed or not rejected: called=%v err=%v", called, err)
	}
}

func TestIntrospectionRejectsPlaintextEndpoint(t *testing.T) {
	_, err := NewIntrospector(IntrospectionConfig{
		Endpoint: "http://localhost/introspect", Issuer: testIssuer, Audience: testAudience,
		ClientID: "acp-client", ClientSecret: "fixture-secret",
	})
	if err == nil {
		t.Fatal("plaintext introspection endpoint accepted")
	}
}

type testPolicy func(context.Context, Identity, Request) (Grant, error)

func (f testPolicy) Authorize(ctx context.Context, id Identity, req Request) (Grant, error) {
	return f(ctx, id, req)
}

func TestBearerResolverAuthenticatesBeforePolicyAndUsesVerifiedSubject(t *testing.T) {
	req := Request{Target: Target{TenantID: "tenant-a", ProjectID: "project-a", AgentID: "agent-a", ReleaseID: "release-a", SessionID: "session-a"}, IdempotencyKey: "key-a", RequestDigest: "sha256:" + fmt.Sprintf("%064d", 1)}
	policyCalls := 0
	policy := testPolicy(func(_ context.Context, id Identity, got Request) (Grant, error) {
		policyCalls++
		if id.Subject != "alice" || id.Issuer != testIssuer || got != req {
			t.Fatal("policy did not receive verified principal and original request")
		}
		return Grant{Target: req.Target, RequestDigest: req.RequestDigest, PrincipalID: "internal-alice", Snapshot: runintent.PrincipalSnapshot{SubjectID: "internal-alice"}}, nil
	})
	resolver := NewBearerResolver(introspectionFixture(t, `{"active":false}`), policy, "opaque-test-token")
	if _, err := resolver.Resolve(context.Background(), req); !errors.Is(err, ErrUnauthenticated) || policyCalls != 0 {
		t.Fatalf("unauthenticated policy call: %d, %v", policyCalls, err)
	}
	resolver = NewBearerResolver(introspectionFixture(t, validIntrospection()), policy, "opaque-test-token")
	grant, err := resolver.Resolve(context.Background(), req)
	if err != nil || grant.PrincipalID != "internal-alice" || policyCalls != 1 {
		t.Fatalf("authenticated grant: %+v / %v / %d", grant, err, policyCalls)
	}
}
