package optimizationgate

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	runpostgres "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestOptimizationAttemptMigrationRejectsNonOwnerACLGrants(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"public table SELECT", "GRANT SELECT ON optimization_verification_attempts TO PUBLIC"},
		{"public column SELECT", "GRANT SELECT (signed_receipt_digest) ON optimization_verification_attempts TO PUBLIC"},
		{"public UPDATE", "GRANT UPDATE ON optimization_verification_attempts TO PUBLIC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := disposableAttemptStore(t)
			if _, err := pool.Exec(context.Background(), tc.sql); err != nil {
				t.Fatalf("inject attempted ACL downgrade: %v", err)
			}
			if err := runpostgres.Migrate(context.Background(), pool); !errors.Is(err, runpostgres.ErrSchemaDrift) {
				t.Fatalf("unsafe non-owner ACL grant not detected: %v", err)
			}
		})
	}
}

func TestUntrustedNonSuperuserCannotIssueConsumeOrReadEvenWithForgedScopeGUC(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	policy, _, _, _ := attemptFixture(t, store)
	ctx := context.Background()
	role := fmt.Sprintf("opt_agent_denied_%d", time.Now().UnixNano())
	roleID := pgx.Identifier{role}.Sanitize()
	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "CREATE ROLE "+roleID+" NOLOGIN NOINHERIT NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DROP OWNED BY "+roleID); err != nil {
			t.Errorf("cleanup agent role grants: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DROP ROLE "+roleID); err != nil {
			t.Errorf("cleanup untrusted role: %v", err)
		}
	})
	if _, err := pool.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO "+roleID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		stmt string
	}{
		{"read", "SELECT * FROM optimization_verification_attempts"},
		{"issue", "INSERT INTO optimization_verification_attempts (verification_nonce,tenant_id,project_id,experiment_id,policy_digest,expires_at) VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','tenant-a','project-a','fake','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',clock_timestamp()+interval '1 hour')"},
		{"consume", "UPDATE optimization_verification_attempts SET consumed_at=clock_timestamp() WHERE verification_nonce='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"},
		{"delete", "DELETE FROM optimization_verification_attempts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+roleID); err != nil {
				t.Fatalf("non-superuser switch failed: %v", err)
			}
			var super, bypass bool
			if err := tx.QueryRow(ctx,
				"SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user").Scan(&super, &bypass); err != nil {
				t.Fatal(err)
			}
			if super || bypass {
				t.Fatal("negative test accidentally used a privileged PostgreSQL identity")
			}
			// app.* variables are freely settable. Prove they do NOT grant
			// table access to an untrusted role absent explicit GRANT.
			if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true), set_config('app.project_id',$2,true)",
				policy.TenantID, policy.ProjectID); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, tc.stmt)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("agent role was not rejected by PostgreSQL ACL (sqlstate 42501): %v", err)
			}
		})
	}
}

func TestOptimizationAttemptMigrationRejectsSameNameWeakVerifierIndex(t *testing.T) {
	for _, tc := range []struct {
		name string
		ddl  string
	}{
		{
			name: "wrong unique key still has same index name",
			ddl:  "CREATE UNIQUE INDEX optimization_attempt_verifier_run_unique ON optimization_verification_attempts (verification_nonce) WHERE consumed_at IS NOT NULL",
		},
		{
			name: "inverted partial predicate",
			ddl:  "CREATE UNIQUE INDEX optimization_attempt_verifier_run_unique ON optimization_verification_attempts (tenant_id,project_id,verifier_run_id) WHERE consumed_at IS NULL",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := disposableAttemptStore(t)
			ctx := context.Background()
			if _, err := pool.Exec(ctx, "DROP INDEX optimization_attempt_verifier_run_unique"); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, tc.ddl); err != nil {
				t.Fatal(err)
			}
			if err := runpostgres.Migrate(ctx, pool); !errors.Is(err, runpostgres.ErrSchemaDrift) {
				t.Fatalf("same-name weak verifier-run deduplication index passed migration: %v", err)
			}
		})
	}
}
