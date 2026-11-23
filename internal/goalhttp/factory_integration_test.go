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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/admission"
	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fixtureGitHubReader models source observations without contacting GitHub.
// Its output must never be presented as upstream GitHub attestation.
type fixtureGitHubReader struct {
	issueReads    int
	baselineReads int
}

func (r *fixtureGitHubReader) Read(_ context.Context, url string) (issuegoal.GitHubIssueSnapshot, error) {
	r.issueReads++
	return issuegoal.GitHubIssueSnapshot{
		Schema: issuegoal.IssueSnapshotVersion, IssueURL: url,
		IssueID: 101, Number: 1, State: "open",
		Digest: "sha256:" + strings.Repeat("4", 64),
	}, nil
}

func (r *fixtureGitHubReader) InspectBaselines(_ context.Context, url, branch, experiment, integration string) (issuegoal.PublicBaselineInspection, error) {
	r.baselineReads++
	return issuegoal.PublicBaselineInspection{
		Schema: issuegoal.PublicBaselineInspectionVersion, IssueURL: url,
		TargetBranch: branch, ExperimentBaselineSHA: experiment,
		IntegrationBaselineSHA: integration, ObservedBranchHeadSHA: integration,
	}, nil
}

func TestCatalogGoalServiceFactoryRejectsAbsentAuthorities(t *testing.T) {
	var absentRepo *runpg.Repository
	var absentAuth *admission.Introspector
	if _, err := NewCatalogGoalServiceFactory(absentRepo, absentAuth); err == nil {
		t.Fatal("missing identity and database authorities were accepted")
	}
	if _, err := NewCatalogGoalServiceFactory(runpg.New(nil), absentAuth); err == nil {
		t.Fatal("missing authenticated identity authority was accepted")
	}
}

func TestCatalogGoalHTTPRealTLSIntrospectionAndPostgres(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("requires an isolated PostgreSQL database via PGTEST_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("test_goalhttp_%d", time.Now().UnixNano())
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

	var issuerURL string
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspect" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if _, _, ok := r.BasicAuth(); !ok {
			http.Error(w, "invalid client", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		token := r.FormValue("token")
		if token != "valid-test-bearer" {
			_, _ = io.WriteString(w, `{"active":false}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true, "iss": issuerURL, "sub": "operator-subject",
			"aud": "acp-control-plane", "client_id": "ci-runner",
			"scope": admission.RunIntentCreateScope, "token_type": "Bearer",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		})
	}))
	defer idp.Close()
	issuerURL = idp.URL
	roots := x509.NewCertPool()
	roots.AddCert(idp.Certificate())
	auth, err := admission.NewIntrospector(admission.IntrospectionConfig{
		Endpoint: issuerURL + "/introspect", Issuer: issuerURL,
		Audience: "acp-control-plane", ClientID: "acp-resource",
		ClientSecret: "ephemeral-test-only",
		HTTPClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"INSERT INTO admission_tenants VALUES ('tenant-a',true)",
		"INSERT INTO admission_projects VALUES ('tenant-a','project-a',true,'policy-v1')",
		"INSERT INTO admission_memberships VALUES ('tenant-a','project-a','principal-a','ci-runner','RUNNER',true)",
		"INSERT INTO admission_releases VALUES ('tenant-a','project-a','coding','release-v1','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',true)",
		"INSERT INTO admission_sessions VALUES ('tenant-a','project-a','session-1','coding','release-v1','principal-a',true)",
	} {
		if strings.HasPrefix(stmt, "INSERT INTO admission_memberships") {
			if _, err := pool.Exec(ctx,
				"INSERT INTO admission_principals VALUES ('tenant-a',$1,'operator-subject','principal-a','subject-a',true)", issuerURL); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	repository := runpg.New(pool)
	factory, err := NewCatalogGoalServiceFactory(repository, auth)
	if err != nil {
		t.Fatal(err)
	}
	reader := &fixtureGitHubReader{}
	source, err := admission.NewTrustedGitHubIssueVerifier(reader, admission.TrustedGitHubIssuePolicy{
		Target: admission.Target{
			TenantID: "tenant-a", ProjectID: "project-a", AgentID: "coding",
			ReleaseID: "release-v1", SessionID: "session-1",
		},
		Repository: "example/repository", TargetBranch: "main",
		AcceptanceRulesDigest: "sha256:" + strings.Repeat("3", 64),
		MaxBudget: issuegoal.Budget{
			MaxTokens: 1000, MaxRuntimeSeconds: 600, MaxSandboxSeconds: 300,
		},
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
	send := func(token string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+SubmitPath, bytes.NewReader(validProposal(t)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, body
	}
	firstCode, first := send("valid-test-bearer")
	if firstCode != http.StatusCreated || first["status"] != "PENDING" || first["created"] != true {
		t.Fatalf("TLS/OAuth/Catalog/Postgres first admission failed: %d %#v", firstCode, first)
	}
	id, ok := first["run_intent_id"].(string)
	if !ok || id == "" {
		t.Fatalf("missing ACP intent identity: %#v", first)
	}
	if replayCode, replay := send("valid-test-bearer"); replayCode != http.StatusOK ||
		replay["run_intent_id"] != id || replay["created"] != false {
		t.Fatalf("idempotent replay created a new intent: HTTP %d %#v", replayCode, replay)
	}
	if deniedCode, _ := send("invalid-test-bearer"); deniedCode != http.StatusUnauthorized {
		t.Fatalf("invalid bearer bypassed identity: %d", deniedCode)
	}
	var intents, events int
	assertCounts := func() {
		t.Helper()
		if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM run_intents), (SELECT count(*) FROM outbox_events)").
			Scan(&intents, &events); err != nil {
			t.Fatal(err)
		}
		if intents != 1 || events != 1 {
			t.Fatalf("duplicate or unauthorized side effects: intents=%d outbox=%d", intents, events)
		}
	}
	assertCounts()
	raw, err := repository.GetExecutionInput(ctx, "tenant-a", id)
	if err != nil || len(raw) == 0 {
		t.Fatalf("canonical input missing from authoritative store: %v", err)
	}
	if reader.issueReads != 2 || reader.baselineReads != 2 {
		t.Fatalf("source was not re-observed for replay: %d %d", reader.issueReads, reader.baselineReads)
	}
	if _, err := pool.Exec(ctx, "UPDATE admission_memberships SET role='VIEWER' WHERE tenant_id='tenant-a'"); err != nil {
		t.Fatal(err)
	}
	if revokedCode, _ := send("valid-test-bearer"); revokedCode != http.StatusForbidden {
		t.Fatalf("catalog revocation bypassed: HTTP %d", revokedCode)
	}
	if reader.issueReads != 2 || reader.baselineReads != 2 {
		t.Fatalf("revoked identity triggered source I/O: %d %d", reader.issueReads, reader.baselineReads)
	}
	assertCounts()
}
