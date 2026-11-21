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
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/admission"
	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pausingGitHubReader is deliberately NOT upstream GitHub evidence. The read
// barrier provides a deterministic point after the initial authority check,
// but before the OAuth/Catalog recheck and any RunIntent/Outbox transaction.
type pausingGitHubReader struct {
	fixtureGitHubReader
	arrived chan struct{}
	release chan struct{}
}

func (r *pausingGitHubReader) Read(ctx context.Context, issueURL string) (issuegoal.GitHubIssueSnapshot, error) {
	select {
	case r.arrived <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return issuegoal.GitHubIssueSnapshot{}, ctx.Err()
	case <-r.release:
		return r.fixtureGitHubReader.Read(ctx, issueURL)
	}
}

func TestGoalHTTPAuthorityRevokedDuringGitHubReadLeavesNoIntentOrOutbox(t *testing.T) {
	if os.Getenv("PGTEST_DSN") == "" {
		t.Skip("requires real disposable PostgreSQL with PGTEST_DSN")
	}
	for _, mode := range []string{"catalog_role_revoked", "oauth_token_revoked"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			dsn := os.Getenv("PGTEST_DSN")
			admin, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			schema := fmt.Sprintf("test_goal_revocation_%d", time.Now().UnixNano())
			if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
				_ = admin.Close(context.Background())
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
				_ = admin.Close(context.Background())
			})
			config, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				t.Fatal(err)
			}
			config.ConnConfig.RuntimeParams["search_path"] = schema
			pool, err := pgxpool.NewWithConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			if err := runpg.Migrate(ctx, pool); err != nil {
				t.Fatal(err)
			}

			var tokenActive atomic.Bool
			tokenActive.Store(true)
			var introspections atomic.Int32
			var issuerURL string
			idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/introspect" || r.Method != http.MethodPost {
					http.NotFound(w, r)
					return
				}
				if clientID, secret, ok := r.BasicAuth(); !ok || clientID != "acp-resource" || secret != "test-secret" {
					http.Error(w, "identity client rejected", http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				introspections.Add(1)
				if r.FormValue("token") != "valid-bearer-for-test" || !tokenActive.Load() {
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
				ClientSecret: "test-secret",
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
			factory, err := NewCatalogGoalServiceFactory(runpg.New(pool), auth)
			if err != nil {
				t.Fatal(err)
			}
			reader := &pausingGitHubReader{
				arrived: make(chan struct{}, 1),
				release: make(chan struct{}),
			}
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
			type response struct {
				status int
				body []byte
				err error
			}
			done := make(chan response, 1)
			preparedGoal := validProposal(t)
			// No sleep or race-based timing: the GitHub reader explicitly signals
			// after the first OAuth + ACP catalog checks have succeeded.
			go func() {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+SubmitPath, bytes.NewReader(preparedGoal))
				if err != nil {
					done <- response{err: err}
					return
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer valid-bearer-for-test")
				res, err := server.Client().Do(req)
				if err != nil {
					done <- response{err: err}
					return
				}
				defer res.Body.Close()
				body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
				done <- response{status: res.StatusCode, body: body, err: err}
			}()
			select {
			case <-reader.arrived:
			case <-ctx.Done():
				close(reader.release)
				t.Fatal("initial OAuth/Catalog preflight did not reach source barrier")
			}
			if introspections.Load() != 1 {
				close(reader.release)
				t.Fatalf("expected exactly one successful preflight introspection, saw %d", introspections.Load())
			}
			switch mode {
			case "catalog_role_revoked":
				if _, err := pool.Exec(ctx, "UPDATE admission_memberships SET role='VIEWER' WHERE tenant_id='tenant-a' AND principal_id='principal-a'"); err != nil {
					close(reader.release)
					t.Fatal(err)
				}
			case "oauth_token_revoked":
				tokenActive.Store(false)
			}
			close(reader.release)
			var actual response
			select {
			case actual = <-done:
			case <-ctx.Done():
				t.Fatal("revoked request did not complete")
			}
			if actual.err != nil {
				t.Fatal(actual.err)
			}
			want := http.StatusForbidden
			if mode == "oauth_token_revoked" {
				want = http.StatusUnauthorized
			}
			if actual.status != want || !bytes.Contains(actual.body, []byte("goal_not_admitted")) {
				t.Fatalf("revocation escaped second check: HTTP %d, body %s, want %d", actual.status, actual.body, want)
			}
			if introspections.Load() != 2 || reader.issueReads != 1 || reader.baselineReads != 1 {
				t.Fatalf("expected preflight + post-read identity checks and one source read: introspections=%d issue=%d baselines=%d",
					introspections.Load(), reader.issueReads, reader.baselineReads)
			}
			var intents, outbox int64
			if err := pool.QueryRow(ctx,
				"SELECT (SELECT count(*) FROM run_intents), (SELECT count(*) FROM outbox_events)").Scan(&intents, &outbox); err != nil {
				t.Fatal(err)
			}
			if intents != 0 || outbox != 0 {
				t.Fatalf("revoked in-flight request created effects: intents=%d outbox=%d", intents, outbox)
			}
		})
	}
}
