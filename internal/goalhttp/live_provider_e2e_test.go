package goalhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/admission"
	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	liveGoalIssueURL = "https://github.com/avaargsh/agent-control-panel/issues/70"
	liveGoalRepoAPI  = "https://api.github.com/repos/avaargsh/agent-control-panel"
)

var liveGoalSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// TestRealGoalHTTPKeycloakGitHubPostgres is an opt-in live E2E admission
// exercise, NEVER a protected-effect test. It reads a real public GitHub
// Issue/branch/commits and uses a disposable TLS Keycloak and PostgreSQL.
// Never enable it against production infrastructure or a long-lived realm.
//
// It intentionally does not require GitHub branch protection: repository
// main may not have protection enabled. This is disclosed as test-only
// source verification, not a production-grade protected release gate.
func TestRealGoalHTTPKeycloakGitHubPostgres(t *testing.T) {
	if os.Getenv("ACP_REAL_GOAL_E2E") != "1" {
		t.Skip("only the disposable Keycloak/PG + live-public-GitHub acceptance job enables this test")
	}
	require := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("live GoalSubmit acceptance requires %s", name)
		}
		return value
	}
	issuer := require("ACP_REAL_IDP_ISSUER")
	issuerCA := require("ACP_REAL_IDP_CA")
	clientSecret := require("ACP_REAL_IDP_SECRET")
	runnerSecret := require("ACP_REAL_RUNNER_SECRET")
	dsn := require("PGTEST_DSN")
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("live acceptance must run in a disposable CI environment, not against a developer or production realm")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	// Derive mutable source selectors from actual api.github.com response
	// immediately before submitting. Do not fake a digest or SHA in this test.
	publicReader := issuegoal.NewPublicIssueReader()
	snapshot, err := publicReader.Read(ctx, liveGoalIssueURL)
	if err != nil || snapshot.State != "open" || snapshot.Number != 70 {
		t.Fatalf("live public GitHub Issue unavailable or changed: %v", err)
	}
	readPublic := func(path string, dest any) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, liveGoalRepoAPI+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "acp-live-goal-acceptance/0.1")
		client := &http.Client{
			Timeout:       12 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("live GitHub source request failed (%s): %v", path, err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("live GitHub source unavailable (%s): HTTP %d", path, res.StatusCode)
		}
		if err := json.NewDecoder(io.LimitReader(res.Body, 64*1024)).Decode(dest); err != nil {
			t.Fatalf("live GitHub source could not be decoded (%s): %v", path, err)
		}
	}
	var target struct {
		Name   string `json:"name"`
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	readPublic("/branches/main", &target)
	if target.Name != "main" || !liveGoalSHA.MatchString(target.Commit.SHA) {
		t.Fatal("live branch HEAD cannot be pinned")
	}
	var headObject struct {
		SHA     string `json:"sha"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	readPublic("/git/commits/"+target.Commit.SHA, &headObject)
	if headObject.SHA != target.Commit.SHA || len(headObject.Parents) == 0 ||
		!liveGoalSHA.MatchString(headObject.Parents[0].SHA) {
		t.Fatal("live independent experiment baseline unavailable")
	}
	// A true two-SHA source observation: experiment=parent of current main,
	// integration=main HEAD. Does not claim experiment/result quality.
	manifest := issuegoal.Manifest{
		SchemaVersion: issuegoal.ManifestVersion,
		Target: issuegoal.Target{
			TenantID: "tenant-a", ProjectID: "project-a", AgentID: "coding",
			ReleaseID: "release-v1", SessionID: "session-1",
		},
		IdempotencyKey:         fmt.Sprintf("github-issue-70-%d", time.Now().UnixNano()),
		IssueURL:               liveGoalIssueURL,
		IssueSnapshotDigest:    snapshot.Digest,
		TargetBranch:           "main",
		ExperimentBaselineSHA:  headObject.Parents[0].SHA,
		IntegrationBaselineSHA: target.Commit.SHA,
		AcceptanceRulesDigest:  "sha256:" + strings.Repeat("3", 64),
		Budget: issuegoal.Budget{
			MaxTokens: 1000, MaxRuntimeSeconds: 600, MaxSandboxSeconds: 300,
		},
	}
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := issuegoal.Prepare(rawManifest)
	if err != nil {
		t.Fatal(err)
	}
	preparedJSON, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("test_goal_live_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := runpg.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	caBytes, err := os.ReadFile(issuerCA)
	if err != nil {
		t.Fatal("disposable IdP CA is unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		t.Fatal("disposable IdP CA invalid")
	}
	authClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: roots, MinVersion: tls.VersionTLS12,
		}},
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer authClient.CloseIdleConnections()
	auth, err := admission.NewIntrospector(admission.IntrospectionConfig{
		Endpoint: issuer + "/protocol/openid-connect/token/introspect", Issuer: issuer,
		Audience: "acp-control-plane", ClientID: "acp-control-plane",
		ClientSecret: clientSecret, HTTPClient: authClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Mint the short-lived token only after all setup and public preflight.
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {admission.RunIntentCreateScope}}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenReq.SetBasicAuth("acp-ci-runner", runnerSecret)
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResp, err := authClient.Do(tokenReq)
	if err != nil {
		t.Fatal("disposable Keycloak token issuance unavailable")
	}
	defer tokenResp.Body.Close()
	var tokenReply struct {
		AccessToken string `json:"access_token"`
	}
	if tokenResp.StatusCode != http.StatusOK ||
		json.NewDecoder(io.LimitReader(tokenResp.Body, 65536)).Decode(&tokenReply) != nil ||
		tokenReply.AccessToken == "" {
		t.Fatalf("disposable Keycloak could not issue a scoped service-account token (HTTP %d)", tokenResp.StatusCode)
	}
	identity, err := auth.Authenticate(ctx, tokenReply.AccessToken)
	if err != nil || identity.Issuer != issuer || identity.ClientID != "acp-ci-runner" {
		t.Fatalf("live Keycloak service-account identity invalid: %v", err)
	}
	for _, stmt := range []string{
		"INSERT INTO admission_tenants VALUES ('tenant-a',true)",
		"INSERT INTO admission_projects VALUES ('tenant-a','project-a',true,'policy-v1')",
		"INSERT INTO admission_memberships VALUES ('tenant-a','project-a','principal-a','acp-ci-runner','RUNNER',true)",
		"INSERT INTO admission_releases VALUES ('tenant-a','project-a','coding','release-v1','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',true)",
		"INSERT INTO admission_sessions VALUES ('tenant-a','project-a','session-1','coding','release-v1','principal-a',true)",
	} {
		if strings.HasPrefix(stmt, "INSERT INTO admission_memberships") {
			if _, err := pool.Exec(ctx, "INSERT INTO admission_principals VALUES ('tenant-a',$1,$2,'principal-a','subject-a',true)",
				identity.Issuer, identity.Subject); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("ACP_REAL_GOAL_PROCESS") == "1" {
		runLiveGoalProcessCLI(t, ctx, liveGoalProcessInput{
			DSN: dsn, Schema: schema, Issuer: issuer, IssuerCA: issuerCA,
			ResourceSecret: clientSecret, Bearer: tokenReply.AccessToken,
			Manifest: manifest, Prepared: preparedJSON,
			RequestDigest: proposal.RequestDigest, Pool: pool,
		})
		return
	}
	factory, err := NewCatalogGoalServiceFactory(runpg.New(pool), auth)
	if err != nil {
		t.Fatal(err)
	}
	source, err := admission.NewTrustedGitHubIssueVerifier(publicReader, admission.TrustedGitHubIssuePolicy{
		Target: admission.Target{
			TenantID: "tenant-a", ProjectID: "project-a", AgentID: "coding",
			ReleaseID: "release-v1", SessionID: "session-1",
		},
		Repository: "avaargsh/agent-control-panel", TargetBranch: "main",
		AcceptanceRulesDigest:  manifest.AcceptanceRulesDigest,
		MaxBudget:              manifest.Budget,
		RequireProtectedBranch: false, // disposable test exception; main currently unprotected
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(factory, source)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()

	submit := func() (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+SubmitPath, bytes.NewReader(preparedJSON))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokenReply.AccessToken)
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("live Go GoalSubmit host transport failed: %v", err)
		}
		defer res.Body.Close()
		var reply map[string]any
		if err := json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&reply); err != nil {
			t.Fatalf("GoalSubmit did not return bounded JSON: %v", err)
		}
		return res.StatusCode, reply
	}
	status, first := submit()
	if status != http.StatusCreated || first["schema"] != AcceptanceVersion ||
		first["request_digest"] != proposal.RequestDigest || first["status"] != "PENDING" ||
		first["created"] != true {
		t.Fatalf("real external provider admission failed: HTTP %d %#v", status, first)
	}
	id, ok := first["run_intent_id"].(string)
	if !ok || id == "" {
		t.Fatalf("missing authoritative RunIntent identity: %#v", first)
	}
	// Live public GitHub re-observation consumes another four API calls and
	// may return 503 due to external source/limit/branch uncertainty. The
	// required CI gate proves ONE true external admission; exact replay has
	// independent deterministic TLS/OAuth/PostgreSQL fault-injection coverage.
	// An operator may opt into a stricter live-provider replay diagnosis. A
	// failed re-observation remains a failure, never a synthetic idempotent 200.
	if os.Getenv("ACP_REAL_GOAL_LIVE_REPLAY") == "1" {
		status2, replay := submit()
		if status2 != http.StatusOK || replay["run_intent_id"] != id ||
			replay["created"] != false || replay["request_digest"] != proposal.RequestDigest {
			t.Fatalf("live provider replay not independently confirmed: HTTP %d %#v", status2, replay)
		}
	}
	var intents, outbox int64
	if err := pool.QueryRow(ctx,
		"SELECT (SELECT count(*) FROM run_intents), (SELECT count(*) FROM outbox_events)").Scan(&intents, &outbox); err != nil {
		t.Fatal(err)
	}
	if intents != 1 || outbox != 1 {
		t.Fatalf("real provider admission wrote unexpected durable authority: intents=%d outbox=%d", intents, outbox)
	}
	expectedInput, _, exactInput, err := issuegoal.DecodePrepared(preparedJSON)
	if err != nil || expectedInput.RequestDigest != proposal.RequestDigest {
		t.Fatalf("cannot independently decode accepted immutable execution input: %v", err)
	}
	gotInput, err := runpg.New(pool).GetExecutionInput(ctx, "tenant-a", id)
	if err != nil || !bytes.Equal(gotInput, exactInput) {
		t.Fatal("accepted live GitHub task input is not backed by the authoritative immutable PostgreSQL record")
	}
	t.Logf("live public GitHub Issue #%d with two real Git SHAs, disposable Keycloak, HTTPS GoalSubmit and PostgreSQL: PASS (first admission only; protected branch and live replay not established)", snapshot.Number)
}
