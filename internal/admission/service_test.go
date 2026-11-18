package admission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type resolverFunc func(context.Context, Request) (Grant, error)

func (f resolverFunc) Resolve(ctx context.Context, req Request) (Grant, error) {
	return f(ctx, req)
}

type captureStore struct {
	calls  int
	intent runintent.Intent
	event  runpg.Event
}

func (s *captureStore) Create(_ context.Context, i runintent.Intent, e runpg.Event) (runintent.Intent, bool, error) {
	s.calls++
	s.intent, s.event = i, e
	return i, true, nil
}

func fixture() (Request, Grant) {
	req := Request{
		Target:         Target{TenantID: "tenant-a", ProjectID: "project-a", AgentID: "agent-a", ReleaseID: "release-a", SessionID: "session-a"},
		IdempotencyKey: "key-a",
		RequestDigest:  "sha256:" + strings.Repeat("a", 64),
	}
	grant := Grant{
		Target: req.Target, RequestDigest: req.RequestDigest, PrincipalID: "authenticated-principal",
		Snapshot: runintent.PrincipalSnapshot{
			Version: runintent.PrincipalSnapshotVersion, ProjectID: req.Target.ProjectID,
			SubjectID: "subject-a", ActorID: "actor-a", PolicyRevision: "policy-a",
			ConfigDigest: "sha256:" + strings.Repeat("b", 64),
		},
	}
	return req, grant
}

func TestAdmitCreatesPendingIntentAndCorrelatedOutboxFromGrant(t *testing.T) {
	req, grant := fixture()
	store := &captureStore{}
	svc := New(store, resolverFunc(func(_ context.Context, got Request) (Grant, error) {
		if got != req {
			t.Fatalf("resolver got unexpected request: %+v", got)
		}
		return grant, nil
	}))
	got, created, err := svc.Admit(context.Background(), req)
	if err != nil || !created || store.calls != 1 {
		t.Fatalf("create=%v calls=%d err=%v", created, store.calls, err)
	}
	if got.Status != runintent.Pending || got.Version != 1 || got.FenceToken != 0 ||
		got.RunID != "" || got.WorkflowID != "" || got.PrincipalID != grant.PrincipalID ||
		got.PrincipalSnapshot != grant.Snapshot || got.TenantID != grant.Target.TenantID ||
		got.ProjectID != grant.Target.ProjectID || got.AgentID != grant.Target.AgentID ||
		got.ReleaseID != grant.Target.ReleaseID || got.SessionID != grant.Target.SessionID ||
		got.RequestDigest != grant.RequestDigest || got.IdempotencyKey != req.IdempotencyKey {
		t.Fatalf("wrong authoritative pending intent: %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	e := store.event
	if e.ID == "" || e.ID == got.ID || e.Producer != "agent-control-panel" ||
		e.Type != "agent.run-intent.created" || e.SchemaVersion != 1 ||
		e.TenantID != got.TenantID || e.AggregateType != "run_intent" ||
		e.AggregateID != got.ID || e.AggregateVersion != 1 ||
		e.CorrelationID != got.ID || e.OccurredAt.IsZero() ||
		string(e.Payload) != fmt.Sprintf(`{"run_intent_id":%q}`, got.ID) {
		t.Fatalf("wrong creation event: %+v", e)
	}
}

func TestAdmitDenialOrInvalidGrantNeverWrites(t *testing.T) {
	req, grant := fixture()
	denial := errors.New("policy denied")
	for _, tc := range []struct {
		name   string
		mutate func(*Grant)
		err    error
	}{
		{name: "denied", err: denial},
		{name: "tenant mismatch", mutate: func(g *Grant) { g.Target.TenantID = "tenant-b" }},
		{name: "project mismatch", mutate: func(g *Grant) { g.Target.ProjectID = "project-b" }},
		{name: "agent mismatch", mutate: func(g *Grant) { g.Target.AgentID = "agent-b" }},
		{name: "release mismatch", mutate: func(g *Grant) { g.Target.ReleaseID = "release-b" }},
		{name: "session mismatch", mutate: func(g *Grant) { g.Target.SessionID = "session-b" }},
		{name: "digest mismatch", mutate: func(g *Grant) { g.RequestDigest = "sha256:" + strings.Repeat("c", 64) }},
		{name: "missing principal", mutate: func(g *Grant) { g.PrincipalID = "" }},
		{name: "missing snapshot", mutate: func(g *Grant) { g.Snapshot = runintent.PrincipalSnapshot{} }},
		{name: "invalid snapshot project", mutate: func(g *Grant) { g.Snapshot.ProjectID = "project-b" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &captureStore{}
			g := grant
			if tc.mutate != nil {
				tc.mutate(&g)
			}
			svc := New(store, resolverFunc(func(context.Context, Request) (Grant, error) { return g, tc.err }))
			_, created, err := svc.Admit(context.Background(), req)
			if err == nil || created || store.calls != 0 {
				t.Fatalf("invalid admission wrote state: created=%v calls=%d err=%v", created, store.calls, err)
			}
		})
	}
}

func TestAdmitInvalidRequestDoesNotInvokeResolver(t *testing.T) {
	req, _ := fixture()
	req.IdempotencyKey = ""
	store := &captureStore{}
	svc := New(store, resolverFunc(func(context.Context, Request) (Grant, error) {
		t.Fatal("malformed request reached resolver")
		return Grant{}, nil
	}))
	if _, _, err := svc.Admit(context.Background(), req); err == nil || store.calls != 0 {
		t.Fatalf("malformed request admitted: %v", err)
	}
}

func TestAdmitPostgresReplayAndPolicyConflict(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("test_admission_%d", time.Now().UnixNano())
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
	req, grant := fixture()
	calls := 0
	var resolveErr error
	svc := New(runpg.New(pool), resolverFunc(func(context.Context, Request) (Grant, error) {
		calls++
		return grant, resolveErr
	}))
	first, created, err := svc.Admit(ctx, req)
	if err != nil || !created {
		t.Fatalf("first create=%v err=%v", created, err)
	}
	second, created, err := svc.Admit(ctx, req)
	if err != nil || created || second.ID != first.ID || calls != 2 {
		t.Fatalf("replay created=%v first=%s second=%s calls=%d err=%v", created, first.ID, second.ID, calls, err)
	}
	// An existing idempotency key must not bypass a fresh policy denial.
	resolveErr = errors.New("grant revoked")
	if _, _, err := svc.Admit(ctx, req); !errors.Is(err, resolveErr) {
		t.Fatalf("revoked policy ignored on replay: %v", err)
	}
	resolveErr = nil
	grant.Snapshot.PolicyRevision = "policy-b"
	if _, _, err := svc.Admit(ctx, req); !errors.Is(err, runpg.ErrIdempotencyConflict) {
		t.Fatalf("changed snapshot must conflict: %v", err)
	}
	var intents, events int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM run_intents), (SELECT count(*) FROM outbox_events)").Scan(&intents, &events); err != nil {
		t.Fatal(err)
	}
	if intents != 1 || events != 1 {
		t.Fatalf("wanted exactly one intent and event; got %d,%d", intents, events)
	}

	// Exercise the real TLS introspector, exact policy and PostgreSQL input
	// transaction together. No fabricated policy response or fake store.
	snapshot, _, inputReq := policyFixture()
	inputReq.IdempotencyKey = "exact-policy-input"
	policy, err := NewExactPolicy(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	tokenBody := strings.TrimSuffix(validIntrospection(), "}") +
		`,"client_id":"approved-client","scope":"acp:run-intent:create"}`
	auth := introspectionFixture(t, tokenBody)
	repo := runpg.New(pool)
	inputSvc := New(repo, NewBearerResolver(auth, policy, "opaque-test-token"))
	raw := []byte(`{ "task": "inspect workload" }`)
	admitted, created, err := inputSvc.AdmitWithInput(ctx, inputReq, raw)
	if err != nil || !created || admitted.PrincipalID != "principal-alice" {
		t.Fatalf("TLS/policy/PG admission failed: %v", err)
	}
	persisted, err := repo.GetExecutionInput(ctx, admitted.TenantID, admitted.ID)
	if err != nil || !bytes.Equal(persisted, raw) {
		t.Fatalf("authorized bytes not persisted: %v", err)
	}
	repeated, created, err := inputSvc.AdmitWithInput(ctx, inputReq, raw)
	if err != nil || created || repeated.ID != admitted.ID {
		t.Fatalf("authorized input replay failed: %v", err)
	}
	snapshot.Grants = nil
	revoked, err := NewExactPolicy(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	revokedSvc := New(repo, NewBearerResolver(auth, revoked, "opaque-test-token"))
	if _, _, err := revokedSvc.AdmitWithInput(ctx, inputReq, raw); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("revoked identity replay accepted: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM run_intents), (SELECT count(*) FROM outbox_events)").Scan(&intents, &events); err != nil {
		t.Fatal(err)
	}
	if intents != 2 || events != 2 {
		t.Fatalf("unexpected writes after scoped admission and denied replay: %d,%d", intents, events)
	}
	for _, stmt := range []string{
		"INSERT INTO admission_tenants VALUES ('tenant-a',true)",
		"INSERT INTO admission_projects VALUES ('tenant-a','project-a',true,'catalog-policy-1')",
		"INSERT INTO admission_principals VALUES ('tenant-a','"+testIssuer+"','alice','catalog-principal','catalog-subject',true)",
		"INSERT INTO admission_memberships VALUES ('tenant-a','project-a','catalog-principal','approved-client','RUNNER',true)",
		"INSERT INTO admission_releases VALUES ('tenant-a','project-a','agent-a','release-a','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',true)",
		"INSERT INTO admission_sessions VALUES ('tenant-a','project-a','session-a','agent-a','release-a','catalog-principal',true)",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	catalog, err := NewCatalogPolicy(repo)
	if err != nil {
		t.Fatal(err)
	}
	catalogSvc := New(repo, NewBearerResolver(auth, catalog, "opaque-test-token"))
	inputReq.IdempotencyKey = "catalog-policy-input"
	catalogRun, created, err := catalogSvc.AdmitWithInput(ctx, inputReq, raw)
	if err != nil || !created || catalogRun.PrincipalID != "catalog-principal" ||
		catalogRun.PrincipalSnapshot.PolicyRevision != "catalog-policy-1" {
		t.Fatalf("catalog-backed admission failed: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE admission_memberships SET role='VIEWER' WHERE tenant_id='tenant-a'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := catalogSvc.AdmitWithInput(ctx, inputReq, raw); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("role downgrade did not revoke replay: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM run_intents), (SELECT count(*) FROM outbox_events)").Scan(&intents, &events); err != nil {
		t.Fatal(err)
	}
	if intents != 3 || events != 3 {
		t.Fatalf("catalog denial wrote unexpected state: %d,%d", intents, events)
	}
}
