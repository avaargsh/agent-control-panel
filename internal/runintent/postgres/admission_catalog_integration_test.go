package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCatalogAdmissionEnforcesRolesAndResourceAttributesAtCommit(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"INSERT INTO admission_tenants VALUES ('tenant-integration',true)",
		"INSERT INTO admission_projects VALUES ('tenant-integration','project-1',true,'policy-1')",
		"INSERT INTO admission_principals VALUES ('tenant-integration','https://identity.example.test','alice','principal-integration','subject-1',true)",
		"INSERT INTO admission_memberships VALUES ('tenant-integration','project-1','principal-integration','client-1','RUNNER',true)",
		"INSERT INTO admission_releases VALUES ('tenant-integration','project-1','agent-1','release-1','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',true)",
		"INSERT INTO admission_sessions VALUES ('tenant-integration','project-1','session-1','agent-1','release-1','principal-integration',true)",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	intent := testIntent(910)
	raw := []byte(`{"task":"read-only"}`)
	var err error
	intent.RequestDigest, err = runintent.ExecutionInputDigest(intent, raw)
	if err != nil {
		t.Fatal(err)
	}
	claims := CatalogClaims{
		Issuer: "https://identity.example.test", Subject: "alice", ClientID: "client-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	binding, err := repo.ResolveCatalogAuthorization(ctx, intent, claims)
	if err != nil || binding.PrincipalID != intent.PrincipalID || binding.Snapshot.SubjectID != "subject-1" {
		t.Fatalf("resolve authorized role: %+v %v", binding, err)
	}
	intent.PrincipalSnapshot = binding.Snapshot
	for _, tc := range []struct {
		name    string
		deny    string
		restore string
	}{
		{"viewer role", "UPDATE admission_memberships SET role='VIEWER'", "UPDATE admission_memberships SET role='RUNNER'"},
		{"revoked client", "UPDATE admission_memberships SET enabled=false", "UPDATE admission_memberships SET enabled=true"},
		{"disabled project", "UPDATE admission_projects SET enabled=false", "UPDATE admission_projects SET enabled=true"},
		{"disabled release", "UPDATE admission_releases SET enabled=false", "UPDATE admission_releases SET enabled=true"},
		{"closed session", "UPDATE admission_sessions SET enabled=false", "UPDATE admission_sessions SET enabled=true"},
		{"disabled tenant", "UPDATE admission_tenants SET enabled=false", "UPDATE admission_tenants SET enabled=true"},
		{"disabled identity", "UPDATE admission_principals SET enabled=false", "UPDATE admission_principals SET enabled=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, tc.deny); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.ResolveCatalogAuthorization(ctx, intent, claims); !errors.Is(err, ErrCatalogDenied) {
				t.Fatalf("revoked authority resolved: %v", err)
			}
			// The already resolved grant is stale; the transaction must
			// recheck the live authority before any durable writes.
			if _, _, err := repo.CreateWithCatalog(ctx, intent, testEvent(intent, 1, 91001, eventCreated), raw, claims); !errors.Is(err, ErrCatalogDenied) {
				t.Fatalf("stale grant persisted: %v", err)
			}
			if _, err := pool.Exec(ctx, tc.restore); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, change := range []func(*runintent.Intent){
		func(i *runintent.Intent) { i.TenantID = "other" },
		func(i *runintent.Intent) { i.ProjectID = "other" },
		func(i *runintent.Intent) { i.AgentID = "other" },
		func(i *runintent.Intent) { i.ReleaseID = "other" },
		func(i *runintent.Intent) { i.SessionID = "other" },
	} {
		changed := intent
		change(&changed)
		if _, err := repo.ResolveCatalogAuthorization(ctx, changed, claims); !errors.Is(err, ErrCatalogDenied) {
			t.Fatalf("foreign resource resolved: %v", err)
		}
	}
	got, created, err := repo.CreateWithCatalog(ctx, intent, testEvent(intent, 1, 91001, eventCreated), raw, claims)
	if err != nil || !created || got.ID != intent.ID {
		t.Fatalf("authorized create: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE admission_projects SET policy_revision='policy-2'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.CreateWithCatalog(ctx, intent, testEvent(intent, 1, 91002, eventCreated), raw, claims); !errors.Is(err, ErrCatalogDenied) {
		t.Fatalf("stale policy revision replay: %v", err)
	}
	if countOutbox(t, pool, intent.ID) != 1 {
		t.Fatal("policy denial changed Outbox")
	}
}

func dropAdmissionCatalogMigrationForTest(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range []string{
		"DROP TABLE admission_sessions",
		"DROP TABLE admission_memberships",
		"DROP TABLE admission_releases",
		"DROP TABLE admission_principals",
		"DROP TABLE admission_projects",
		"DROP TABLE admission_tenants",
		"DELETE FROM schema_migrations WHERE version=11",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdmissionCatalogMigrationRejectsWeakenedRoleConstraint(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "ALTER TABLE admission_memberships DROP CONSTRAINT admission_memberships_role_check"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("weakened role constraint accepted: %v", err)
	}
}
