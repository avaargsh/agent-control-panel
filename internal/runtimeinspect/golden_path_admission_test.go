package runtimeinspect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/admission"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This fixture provisions only the isolated CI catalog and uses the
// genuine issuer's access token. No fake grant or direct RunIntent insert
// is allowed on the primary Golden Path.
func admitGoldenPathWithLiveIssuer(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo *runpg.Repository, target runintent.Intent, input []byte) runintent.Intent {
	t.Helper()
	auth, token := provisionLiveIssuerCatalog(t, ctx, pool, target)
	policy, err := admission.NewCatalogPolicy(repo)
	if err != nil {
		t.Fatal(err)
	}
	service := admission.New(repo, admission.NewBearerResolver(auth, policy, token))
	request := admission.Request{
		Target: admission.Target{
			TenantID: target.TenantID, ProjectID: target.ProjectID, AgentID: target.AgentID,
			ReleaseID: target.ReleaseID, SessionID: target.SessionID,
		},
		IdempotencyKey: target.IdempotencyKey,
	}
	first, created, err := service.AdmitWithInput(ctx, request, input)
	if err != nil || !created || first.Status != runintent.Pending || first.PrincipalID != target.PrincipalID ||
		first.PrincipalSnapshot.SubjectID != target.PrincipalSnapshot.SubjectID ||
		first.PrincipalSnapshot.ActorID != first.PrincipalSnapshot.SubjectID ||
		first.PrincipalSnapshot.PolicyRevision != target.PrincipalSnapshot.PolicyRevision {
		t.Fatalf("live OAuth/catalog atomic admission failed: %v", err)
	}
	got, err := repo.GetExecutionInput(ctx, first.TenantID, first.ID)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("admitted execution input differs: %v", err)
	}
	replay, created, err := service.AdmitWithInput(ctx, request, input)
	if err != nil || created || replay.ID != first.ID {
		t.Fatalf("live admission replay changed identity: %v", err)
	}
	// Verify denial on a live token after role revocation, restore only the
	// disposable catalog so the following admitted run test stays authorized.
	if _, err := pool.Exec(ctx, "UPDATE admission_memberships SET role='VIEWER' WHERE tenant_id=$1", first.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AdmitWithInput(ctx, request, input); !errors.Is(err, admission.ErrPolicyDenied) {
		t.Fatalf("live issuer plus revoked role admitted replay: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE admission_memberships SET role='RUNNER' WHERE tenant_id=$1", first.TenantID); err != nil {
		t.Fatal(err)
	}
	return first
}

// provisionLiveIssuerCatalog binds the fixture only to an introspected identity.
func provisionLiveIssuerCatalog(t *testing.T, ctx context.Context, pool *pgxpool.Pool, target runintent.Intent) (*admission.Introspector, string) {
	t.Helper()
	if os.Getenv("ACP_REAL_IDP") != "1" {
		t.Fatal("Golden Path must use the actual isolated OIDC issuer")
	}
	required := func(name string) string {
		t.Helper()
		if got := os.Getenv(name); got != "" {
			return got
		}
		t.Fatalf("Golden Path missing %s", name)
		return ""
	}
	issuer := required("ACP_REAL_IDP_ISSUER")
	certs, err := os.ReadFile(required("ACP_REAL_IDP_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certs) {
		t.Fatal("invalid isolated identity CA")
	}
	h := &http.Client{
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}},
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(h.CloseIdleConnections)
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {admission.RunIntentCreateScope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	const oauthClient = "acp-ci-runner"
	const resource = "acp-control-plane"
	req.SetBasicAuth(oauthClient, required("ACP_REAL_RUNNER_SECRET"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := h.Do(req)
	if err != nil {
		t.Fatal("actual issuer token endpoint unavailable")
	}
	defer res.Body.Close()
	var issued struct {
		Token string `json:"access_token"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&issued) != nil || issued.Token == "" {
		t.Fatalf("actual issuer token creation failed: %d", res.StatusCode)
	}
	auth, err := admission.NewIntrospector(admission.IntrospectionConfig{
		Endpoint: issuer + "/protocol/openid-connect/token/introspect",
		Issuer:   issuer, Audience: resource, ClientID: resource,
		ClientSecret: required("ACP_REAL_IDP_SECRET"), HTTPClient: h,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := auth.Authenticate(ctx, issued.Token)
	if err != nil || identity.Issuer != issuer || identity.ClientID != oauthClient || identity.Subject == "" {
		t.Fatalf("real identity admission binding failed: %v", err)
	}
	// Test-only catalog provisioning uses verified issuer + subject. The
	// normal admission policy independently reauthenticates the bearer.
	for _, row := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO admission_tenants VALUES ($1,true)", []any{target.TenantID}},
		{"INSERT INTO admission_projects VALUES ($1,$2,true,$3)", []any{target.TenantID, target.ProjectID, target.PrincipalSnapshot.PolicyRevision}},
		{"INSERT INTO admission_principals VALUES ($1,$2,$3,$4,$5,true)", []any{target.TenantID, identity.Issuer, identity.Subject, target.PrincipalID, target.PrincipalSnapshot.SubjectID}},
		{"INSERT INTO admission_memberships VALUES ($1,$2,$3,$4,'RUNNER',true)", []any{target.TenantID, target.ProjectID, target.PrincipalID, oauthClient}},
		{"INSERT INTO admission_releases VALUES ($1,$2,$3,$4,$5,true)", []any{target.TenantID, target.ProjectID, target.AgentID, target.ReleaseID, target.PrincipalSnapshot.ConfigDigest}},
		{"INSERT INTO admission_sessions VALUES ($1,$2,$3,$4,$5,$6,true)", []any{target.TenantID, target.ProjectID, target.SessionID, target.AgentID, target.ReleaseID, target.PrincipalID}},
	} {
		if _, err := pool.Exec(ctx, row.sql, row.args...); err != nil {
			t.Fatal(err)
		}
	}
	return auth, issued.Token
}
