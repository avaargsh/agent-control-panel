package admission

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual PostgreSQL catalog, RunIntent and Outbox: two independent principals
// own the same logical Project/Agent/Release/Session names and idempotency key.
// The fake here replaces only external OAuth introspection (which has a
// separate real IdP test), not ACP policy, admission, transactions or storage.
func TestTwoTenantCatalogScopesRealPostgres(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("test_tenant_matrix_%d", time.Now().UnixNano())
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
	repo := runpg.New(pool)
	policy, err := NewCatalogPolicy(repo)
	if err != nil {
		t.Fatal(err)
	}
	type actor struct {
		tenant, subject, principal, digest string
	}
	actors := []actor{
		{"tenant-a", "alice", "principal-shared", "sha256:" + repeatDigest("a")},
		{"tenant-b", "bob", "principal-shared", "sha256:" + repeatDigest("b")},
	}
	const (
		project = "shared-project"
		agent   = "shared-agent"
		release = "shared-release"
		session = "shared-session"
		client  = "shared-oauth-client"
	)
	for _, actor := range actors {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO admission_tenants VALUES ($1,true)", []any{actor.tenant}},
			{"INSERT INTO admission_projects VALUES ($1,$2,true,'revision-1')", []any{actor.tenant, project}},
			{"INSERT INTO admission_principals VALUES ($1,$2,$3,$4,$5,true)",
				[]any{actor.tenant, testIssuer, actor.subject, actor.principal, actor.subject}},
			{"INSERT INTO admission_memberships VALUES ($1,$2,$3,$4,'RUNNER',true)",
				[]any{actor.tenant, project, actor.principal, client}},
			{"INSERT INTO admission_releases VALUES ($1,$2,$3,$4,$5,true)",
				[]any{actor.tenant, project, agent, release, actor.digest}},
			{"INSERT INTO admission_sessions VALUES ($1,$2,$3,$4,$5,$6,true)",
				[]any{actor.tenant, project, session, agent, release, actor.principal}},
		} {
			if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	request := func(tenant string) Request {
		return Request{Target: Target{TenantID: tenant, ProjectID: project, AgentID: agent,
			ReleaseID: release, SessionID: session}, IdempotencyKey: "same-retry-key"}
	}
	svc := func(who actor) *Service {
		id := Identity{Issuer: testIssuer, Subject: who.subject, ClientID: client,
			Scope: RunIntentCreateScope, ExpiresAt: time.Now().Add(30 * time.Minute)}
		return New(repo, NewBearerResolver(policyTestAuthenticator{id}, policy, "fixture-token"))
	}
	raw := []byte(`{"objective":"inspect"}`)
	ownA := svc(actors[0])
	ownB := svc(actors[1])
	if _, created, err := ownA.AdmitWithInput(ctx, request(actors[1].tenant), raw); err != ErrPolicyDenied || created {
		t.Fatalf("tenant A accessed existing tenant B resource: created=%v err=%v", created, err)
	}
	if _, created, err := ownB.AdmitWithInput(ctx, request(actors[0].tenant), raw); err != ErrPolicyDenied || created {
		t.Fatalf("tenant B accessed existing tenant A resource: created=%v err=%v", created, err)
	}
	first, created, err := ownA.AdmitWithInput(ctx, request(actors[0].tenant), raw)
	if err != nil || !created || first.TenantID != actors[0].tenant {
		t.Fatalf("tenant A admission failed: created=%v err=%v", created, err)
	}
	second, created, err := ownB.AdmitWithInput(ctx, request(actors[1].tenant), raw)
	if err != nil || !created || second.TenantID != actors[1].tenant {
		t.Fatalf("tenant B admission failed: created=%v err=%v", created, err)
	}
	if first.ID == second.ID || first.RequestDigest == second.RequestDigest {
		t.Fatal("cross-tenant intents collided despite distinct authority binding")
	}
	for _, tc := range []struct {
		service *Service
		tenant  string
		id      string
	}{
		{ownA, actors[0].tenant, first.ID},
		{ownB, actors[1].tenant, second.ID},
	} {
		replay, created, err := tc.service.AdmitWithInput(ctx, request(tc.tenant), raw)
		if err != nil || created || replay.ID != tc.id {
			t.Fatalf("same-tenant replay lost idempotency: created=%v err=%v", created, err)
		}
	}
	for _, tc := range []struct{ tenant, ownID, foreignID string }{
		{actors[0].tenant, first.ID, second.ID},
		{actors[1].tenant, second.ID, first.ID},
	} {
		if got, err := repo.GetExecutionInput(ctx, tc.tenant, tc.ownID); err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("own RunIntent input unavailable: %v", err)
		}
		if got, err := repo.GetExecutionInput(ctx, tc.tenant, tc.foreignID); err == nil || len(got) != 0 {
			t.Fatalf("cross-tenant RunIntent input leaked: bytes=%d err=%v", len(got), err)
		}
		var intents, events int
		if err := pool.QueryRow(ctx,
			"SELECT (SELECT count(*) FROM run_intents WHERE tenant_id=$1), (SELECT count(*) FROM outbox_events WHERE tenant_id=$1)",
			tc.tenant).Scan(&intents, &events); err != nil || intents != 1 || events != 1 {
			t.Fatalf("foreign write or replay escaped tenant partition: intents=%d events=%d err=%v", intents, events, err)
		}
	}

	// Test-only ACCEPTED fixture: Runtime alone owns real Run creation and
	// acceptance receipts. This exercises the actual ACP authority projection,
	// not the independent Runtime receipt or Temporal state security.
	runs := []struct {
		intent runintent.Intent
		runID  string
	}{
		{first, "11111111-1111-4111-8111-111111111111"},
		{second, "22222222-2222-4222-8222-222222222222"},
	}
	for _, run := range runs {
		if _, err := pool.Exec(ctx, `UPDATE run_intents
			SET status='ACCEPTED',runtime_run_id=$3,workflow_id=$4,version=version+1
			WHERE id=$1::uuid AND tenant_id=$2`,
			run.intent.ID, run.intent.TenantID, run.runID, "agent-run/v1/"+run.runID); err != nil {
			t.Fatal(err)
		}
		ref := runpg.ExecutionAuthorityRef{
			TenantID: run.intent.TenantID, RunIntentID: run.intent.ID,
			RunID: run.runID, RequestDigest: run.intent.RequestDigest,
		}
		if current, err := repo.GetExecutionAuthority(ctx, ref); err != nil || current.Ref != ref {
			t.Fatalf("own tenant lost accepted Run authority: %v", err)
		}
		foreign := ref
		if ref.TenantID == actors[0].tenant {
			foreign.TenantID = actors[1].tenant
		} else {
			foreign.TenantID = actors[0].tenant
		}
		if _, err := repo.GetExecutionAuthority(ctx, foreign); err != runpg.ErrCatalogDenied {
			t.Fatalf("foreign tenant acquired an existing Run authority: %v", err)
		}
	}
}

func repeatDigest(ch string) string {
	var out [64]byte
	for i := range out {
		out[i] = ch[0]
	}
	return string(out[:])
}
