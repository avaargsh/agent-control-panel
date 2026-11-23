package optimizationgate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// A separate LOGIN session is materially stronger evidence than SET LOCAL
// ROLE inside the schema-owner connection. Neither app.* GUC nor schema USAGE
// grants this credential access to the review receipt journal.
func TestIndependentUntrustedLoginCannotUseOptimizationAttemptJournal(t *testing.T) {
	store, owner := disposableAttemptStore(t)
	policy, _, _, _ := attemptFixture(t, store)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	var schema string
	if err := owner.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := fmt.Sprintf("acp_opt_agent_login_%d", time.Now().UnixNano())
	roleSQL := pgx.Identifier{role}.Sanitize()
	passwordBytes := make([]byte, 24)
	if _, err := rand.Read(passwordBytes); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(passwordBytes)
	// The role is disposable and receives only USAGE on a disposable schema.
	if _, err := owner.Exec(ctx, "CREATE ROLE "+roleSQL+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := owner.Exec(context.Background(), "DROP OWNED BY "+roleSQL); err != nil {
			t.Errorf("revoke disposable login grants: %v", err)
		}
		if _, err := owner.Exec(context.Background(), "DROP ROLE "+roleSQL); err != nil {
			t.Errorf("remove disposable login: %v", err)
		}
	})
	if _, err := owner.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO "+roleSQL); err != nil {
		t.Fatal(err)
	}

	cfg, err := pgx.ParseConfig(os.Getenv("PGTEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.User = role
	cfg.Password = password
	cfg.RuntimeParams["search_path"] = schema
	agent, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("separate non-superuser PostgreSQL LOGIN connection failed: %v", err)
	}
	defer func() { _ = agent.Close(context.Background()) }()

	var sessionUser, currentUser string
	var super, bypass bool
	if err := agent.QueryRow(ctx,
		"SELECT session_user,current_user,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user",
	).Scan(&sessionUser, &currentUser, &super, &bypass); err != nil {
		t.Fatal(err)
	}
	if sessionUser != role || currentUser != role || super || bypass {
		t.Fatalf("not authenticated as independent unprivileged LOGIN: session=%q current=%q super=%v bypass=%v", sessionUser, currentUser, super, bypass)
	}
	// Simulate an Agent sending arbitrary tenant/project GUCs over its own
	// authenticated connection; authentication must not derive from GUCs.
	if _, err := agent.Exec(ctx,
		"SELECT set_config('app.tenant_id',$1,false),set_config('app.project_id',$2,false)",
		policy.TenantID, policy.ProjectID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"read", "SELECT count(*) FROM optimization_verification_attempts"},
		{"issue", "INSERT INTO optimization_verification_attempts (verification_nonce,tenant_id,project_id,experiment_id,policy_digest,expires_at) VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','tenant-a','project-a','fake','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',clock_timestamp()+interval '1 hour')"},
		{"consume", "UPDATE optimization_verification_attempts SET consumed_at=clock_timestamp() WHERE verification_nonce='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"},
		{"delete", "DELETE FROM optimization_verification_attempts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := agent.Exec(ctx, tc.sql)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("separate LOGIN with forged GUC should get 42501; got %v", err)
			}
		})
	}
}
