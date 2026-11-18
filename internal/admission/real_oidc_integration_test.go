package admission

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Only the dedicated live-issuer workflow enables this test. It fails
// rather than skips once enabled, including missing CA/DB/provider config.
func TestRealOIDCServiceAccountCatalogAdmission(t *testing.T) {
	if os.Getenv("ACP_REAL_IDP") != "1" {
		t.Skip("dedicated disposable Keycloak/PostgreSQL integration only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	required := func(name string) string {
		t.Helper()
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("live identity test requires %s", name)
		}
		return v
	}
	issuer := required("ACP_REAL_IDP_ISSUER")
	dsn := required("PGTEST_DSN")
	secret := required("ACP_REAL_IDP_SECRET")
	runnerSecret := required("ACP_REAL_RUNNER_SECRET")
	certs, err := os.ReadFile(required("ACP_REAL_IDP_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certs) {
		t.Fatal("invalid isolated issuer CA")
	}
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}},
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(httpClient.CloseIdleConnections)
	const resource = "acp-control-plane"
	const runner = "acp-ci-runner"
	makeAuth := func(iss, aud string) *Introspector {
		t.Helper()
		auth, err := NewIntrospector(IntrospectionConfig{
			Endpoint: issuer + "/protocol/openid-connect/token/introspect",
			Issuer: iss, Audience: aud, ClientID: resource, ClientSecret: secret, HTTPClient: httpClient,
		})
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}
	mint := func(scope string) string {
		t.Helper()
		form := url.Values{"grant_type": {"client_credentials"}}
		if scope != "" {
			form.Set("scope", scope)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(runner, runnerSecret)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := httpClient.Do(req)
		if err != nil {
			t.Fatal("real issuer token endpoint unavailable")
		}
		defer res.Body.Close()
		var issued struct {
			AccessToken string `json:"access_token"`
		}
		if res.StatusCode != http.StatusOK ||
			json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&issued) != nil || !validBearer(issued.AccessToken) {
			t.Fatalf("real issuer failed to mint service-account token: HTTP %d", res.StatusCode)
		}
		return issued.AccessToken
	}
	// Migrate before issuing the short-lived credentials.
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("test_real_oidc_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := runpg.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	token := mint(RunIntentCreateScope)
	auth := makeAuth(issuer, resource)
	id, err := auth.Authenticate(ctx, token)
	if err != nil || id.Issuer != issuer || id.ClientID != runner ||
		!hasCreateScope(id.Scope) || !id.ExpiresAt.After(time.Now()) {
		t.Fatalf("real issuer claims failed strict binding: %v", err)
	}
	for _, invalid := range []*Introspector{makeAuth(issuer+"/wrong", resource), makeAuth(issuer, "other-audience")} {
		if _, err := invalid.Authenticate(ctx, token); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("foreign issuer/audience admitted: %v", err)
		}
	}
	if _, err := auth.Authenticate(ctx, "invalid-token"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("invalid token accepted: %v", err)
	}
	for _, stmt := range []string{
		"INSERT INTO admission_tenants VALUES ('tenant-a',true)",
		"INSERT INTO admission_projects VALUES ('tenant-a','project-a',true,'catalog-policy-1')",
		"INSERT INTO admission_memberships VALUES ('tenant-a','project-a','catalog-principal','acp-ci-runner','RUNNER',true)",
		"INSERT INTO admission_releases VALUES ('tenant-a','project-a','agent-a','release-a','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',true)",
		"INSERT INTO admission_sessions VALUES ('tenant-a','project-a','session-a','agent-a','release-a','catalog-principal',true)",
	} {
		if strings.HasPrefix(stmt, "INSERT INTO admission_memberships") {
			// Bind the independently verified issuer+subject, never decode
			// the JWT ourselves or accept a subject supplied by the Agent.
			if _, err := pool.Exec(ctx, "INSERT INTO admission_principals VALUES('tenant-a',$1,$2,'catalog-principal','catalog-subject',true)", id.Issuer, id.Subject); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	repo := runpg.New(pool)
	policy, err := NewCatalogPolicy(repo)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := fixture()
	request.RequestDigest = ""
	request.IdempotencyKey = "live-issuer"
	raw := []byte(`{"task":"read-only verification"}`)
	service := New(repo, NewBearerResolver(auth, policy, token))
	admitted, created, err := service.AdmitWithInput(ctx, request, raw)
	if err != nil || !created || admitted.PrincipalID != "catalog-principal" ||
		admitted.PrincipalSnapshot.SubjectID != "catalog-subject" {
		t.Fatalf("live issuer -> catalog -> atomic input admission failed: %v", err)
	}
	got, err := repo.GetExecutionInput(ctx, admitted.TenantID, admitted.ID)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("authorized input mismatch: %v", err)
	}
	replay, created, err := service.AdmitWithInput(ctx, request, raw)
	if err != nil || created || replay.ID != admitted.ID {
		t.Fatalf("real identity replay failed: %v", err)
	}
	noScope := mint("")
	if _, _, err := New(repo, NewBearerResolver(auth, policy, noScope)).AdmitWithInput(ctx, request, raw); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("token without required scope bypassed policy: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE admission_memberships SET role='VIEWER'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AdmitWithInput(ctx, request, raw); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("role revocation bypassed by live bearer replay: %v", err)
	}
	// Expiration is tested against the actual IdP, not a fabricated claim.
	wait := time.Until(id.ExpiresAt) + 2*time.Second
	if wait > time.Minute {
		t.Fatal("test issuer did not mint a short-lived access token")
	}
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal("timed out before actual token expired")
		case <-timer.C:
		}
	}
	if _, err := auth.Authenticate(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired real access token accepted: %v", err)
	}
	var intents, events int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM run_intents), (SELECT count(*) FROM outbox_events)").Scan(&intents, &events); err != nil {
		t.Fatal(err)
	}
	if intents != 1 || events != 1 {
		t.Fatalf("denied live identity wrote tasks: %d/%d", intents, events)
	}
}
