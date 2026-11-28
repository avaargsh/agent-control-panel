package runtimeinspect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/admission"
	"github.com/avaargsh/agent-control-panel/internal/goalhttp"
	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Require fresh, dedicated loopback databases; the test provisions owner-side
// fixtures and sends no GitHub mutation or real task to any external service.
func requireDisposableIssueRecovery(t *testing.T, acpDSN, runtimeDSN string) {
	t.Helper()
	for _, spec := range []struct{ dsn, database string }{
		{acpDSN, "/acp72_disposable"}, {runtimeDSN, "/runtime72_disposable"},
	} {
		u, err := url.Parse(spec.dsn)
		if err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" ||
			u.Port() == "" || u.Path != spec.database || u.RawQuery != "sslmode=disable" || u.Fragment != "" {
			t.Fatal("Issue recovery requires named disposable loopback PostgreSQL databases")
		}
	}
	u, err := url.Parse(os.Getenv("ACP_REAL_IDP_ISSUER"))
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" ||
		u.Port() == "" || u.Path != "/realms/acp-ci" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("Issue recovery requires a disposable loopback ACP issuer")
	}
}

// Reject an accidentally reused local database before either service migrates.
func requireEmptyIssueRecoveryDatabase(t *testing.T, ctx context.Context, dsn, name string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("disposable PostgreSQL could not be opened")
	}
	defer conn.Close(ctx)
	var empty bool
	err = conn.QueryRow(ctx, `
		SELECT pg_catalog.current_database() = $1 AND NOT EXISTS (
			SELECT 1 FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_'
		)`, name).Scan(&empty)
	if err != nil || !empty {
		t.Fatalf("requires a fresh disposable PostgreSQL database: %s", name)
	}
}

func admitDisposableGitHubIssue(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo *runpg.Repository, fixture runintent.Intent) (runintent.Intent, []byte) {
	t.Helper()
	const issueURL = "https://github.com/avaargsh/tmp/issues/1"
	const rootSHA = "c40b13960956eab74c5061e1cac8887194a70d3f"
	public := issuegoal.NewPublicIssueReader()
	snapshot, err := public.Read(ctx, issueURL)
	if err != nil || snapshot.State != "open" || snapshot.Number != 1 || snapshot.IssueID != 6669115673 {
		t.Fatalf("disposable public Issue identity unavailable: %v", err)
	}
	target := issuegoal.Target{TenantID: fixture.TenantID, ProjectID: fixture.ProjectID, AgentID: fixture.AgentID, ReleaseID: fixture.ReleaseID, SessionID: fixture.SessionID}
	manifest := issuegoal.Manifest{SchemaVersion: issuegoal.ManifestVersion, Target: target, IdempotencyKey: fixture.IdempotencyKey,
		IssueURL: issueURL, IssueSnapshotDigest: snapshot.Digest, TargetBranch: "main",
		ExperimentBaselineSHA: rootSHA, IntegrationBaselineSHA: rootSHA,
		AcceptanceRulesDigest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("tmp issue recovery only; no execution or write permission"))),
		Budget:                issuegoal.Budget{MaxTokens: 1000, MaxRuntimeSeconds: 600, MaxSandboxSeconds: 300},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuegoal.Prepare(raw)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	_, _, exactInput, err := issuegoal.DecodePrepared(body)
	if err != nil {
		t.Fatal(err)
	}
	auth, token := provisionLiveIssuerCatalog(t, ctx, pool, fixture)
	factory, err := goalhttp.NewCatalogGoalServiceFactory(repo, auth)
	if err != nil {
		t.Fatal(err)
	}
	source, err := admission.NewTrustedGitHubIssueVerifier(public, admission.TrustedGitHubIssuePolicy{
		Target:     admission.Target{TenantID: target.TenantID, ProjectID: target.ProjectID, AgentID: target.AgentID, ReleaseID: target.ReleaseID, SessionID: target.SessionID},
		Repository: "avaargsh/tmp", TargetBranch: manifest.TargetBranch, AcceptanceRulesDigest: manifest.AcceptanceRulesDigest, MaxBudget: manifest.Budget,
		RequireProtectedBranch: false, // this disposable repository is unprotected; never an authorization signal
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := goalhttp.NewHandler(factory, source)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	submit := func(want int, created bool) string {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+goalhttp.SubmitPath, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("GoalSubmit HTTP %d, want %d", res.StatusCode, want)
		}
		if want == http.StatusForbidden {
			return ""
		}
		var receipt struct {
			Schema  string           `json:"schema"`
			ID      string           `json:"run_intent_id"`
			Digest  string           `json:"request_digest"`
			Status  runintent.Status `json:"status"`
			Created bool             `json:"created"`
		}
		if err := json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&receipt); err != nil ||
			receipt.Schema != goalhttp.AcceptanceVersion || receipt.ID == "" || receipt.Digest != prepared.RequestDigest ||
			receipt.Status != runintent.Pending || receipt.Created != created {
			t.Fatalf("GoalSubmit returned invalid durable receipt: %v", err)
		}
		return receipt.ID
	}
	id := submit(http.StatusCreated, true)
	if replay := submit(http.StatusOK, false); replay != id {
		t.Fatal("exact live Issue replay changed RunIntent")
	}
	setMembership := func(enabled bool) {
		t.Helper()
		tag, err := pool.Exec(ctx, "UPDATE admission_memberships SET enabled=$1 WHERE tenant_id=$2 AND project_id=$3 AND principal_id=$4 AND client_id='acp-ci-runner'", enabled, fixture.TenantID, fixture.ProjectID, fixture.PrincipalID)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("disposable membership update failed: %v", err)
		}
	}
	setMembership(false)
	submit(http.StatusForbidden, false)
	var intents, events int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM run_intents), (SELECT count(*) FROM outbox_events)").Scan(&intents, &events); err != nil || intents != 1 || events != 1 {
		t.Fatalf("admission or denied replay mutated RunIntent/Outbox unexpectedly: %d/%d (%v)", intents, events, err)
	}
	setMembership(true) // restore only the disposable catalog before dispatch
	intent, err := repo.Get(ctx, fixture.TenantID, id)
	if err != nil || intent.Status != runintent.Pending || intent.RequestDigest != prepared.RequestDigest ||
		intent.PrincipalID != fixture.PrincipalID || intent.PrincipalSnapshot.ConfigDigest != fixture.PrincipalSnapshot.ConfigDigest {
		t.Fatalf("live Issue receipt did not match PostgreSQL authority: %v", err)
	}
	persisted, err := repo.GetExecutionInput(ctx, fixture.TenantID, id)
	if err != nil || !bytes.Equal(persisted, exactInput) {
		t.Fatalf("live Issue execution input differs from persisted input: %v", err)
	}
	t.Log("live GitHub Issue + HTTPS Keycloak GoalSubmit: created, replayed same receipt, denied revoked membership")
	return intent, persisted
}
