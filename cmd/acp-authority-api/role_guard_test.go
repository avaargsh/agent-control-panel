package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real PostgreSQL LOGIN + privileges: no fake row scanner or session SET ROLE.
// PGTEST_DSN must be an isolated test database with CREATE ROLE permission.
// This is not evidence of production role provisioning or tenant-scoped RLS.
func TestAuthorityDatabaseRoleFailClosed(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	schema, role := "acp_authority_role_"+suffix, "acp_authority_reader_"+suffix
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	owner, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := runpg.Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	// The migrator/table owner MUST NOT pass despite readonly transactions.
	if err := verifyAuthorityDatabaseRole(ctx, owner); err == nil {
		t.Fatal("migration owner was accepted as authority reader")
	}

	// A read-only authority identity must not inherit access to unrelated
	// application schemas in the same database. This sibling schema is NOT
	// on the test connection's search_path, so ordinary same-schema checks
	// must not be allowed to conceal the grant.
	foreignSchema := "acp_authority_foreign_" + suffix
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+foreignSchema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+foreignSchema+" CASCADE")
	if _, err := admin.Exec(ctx, "CREATE TABLE "+foreignSchema+".secret (id bigint, payload text)"); err != nil {
		t.Fatal(err)
	}

	passwordBytes := make([]byte, 24)
	if _, err := rand.Read(passwordBytes); err != nil {
		t.Fatal(err)
	}
	password := fmt.Sprintf("%x", passwordBytes)
	if _, err := admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(context.Background(), "DROP OWNED BY "+role); err != nil {
			t.Errorf("revoke test role grants: %v", err)
		}
		if _, err := admin.Exec(context.Background(), "DROP ROLE "+role); err != nil {
			t.Errorf("drop test role: %v", err)
		}
	}()

	for _, statement := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT SELECT ON " + schema + "." + strings.Join([]string{
			"run_intents", "admission_tenants", "admission_projects",
			"admission_principals", "admission_memberships",
			"admission_releases", "admission_sessions",
		}, ", "+schema+".") + " TO " + role,
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	readerConfig := cfg.Copy()
	readerConfig.ConnConfig.User = role
	readerConfig.ConnConfig.Password = password
	reader, err := pgxpool.NewWithConfig(ctx, readerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var currentUser, sessionUser string
	if err := reader.QueryRow(ctx, "SELECT current_user, session_user").Scan(&currentUser, &sessionUser); err != nil {
		t.Fatal(err)
	}
	if currentUser != role || sessionUser != role {
		t.Fatalf("expected independently authenticated role, current=%q session=%q", currentUser, sessionUser)
	}
	check := func(t *testing.T, wantAllowed bool) {
		t.Helper()
		err := verifyAuthorityDatabaseRole(ctx, reader)
		if (err == nil) != wantAllowed {
			t.Fatalf("authority database guard: allowed=%v want=%v err=%v", err == nil, wantAllowed, err)
		}
	}
	check(t, true)

	// Any grant beyond the exact seven authority relations must fail startup.
	for _, tc := range []struct {
		name   string
		grant  string
		revoke string
	}{
		{"write intent", "GRANT UPDATE ON " + schema + ".run_intents TO " + role,
			"REVOKE UPDATE ON " + schema + ".run_intents FROM " + role},
		{"read outbox", "GRANT SELECT ON " + schema + ".outbox_events TO " + role,
			"REVOKE SELECT ON " + schema + ".outbox_events FROM " + role},
		{"read outbox column only", "GRANT SELECT (payload) ON " + schema + ".outbox_events TO " + role,
			"REVOKE SELECT (payload) ON " + schema + ".outbox_events FROM " + role},
		{"update intent column only", "GRANT UPDATE (updated_at) ON " + schema + ".run_intents TO " + role,
			"REVOKE UPDATE (updated_at) ON " + schema + ".run_intents FROM " + role},
		{"public read outbox column", "GRANT SELECT (payload) ON " + schema + ".outbox_events TO PUBLIC",
			"REVOKE SELECT (payload) ON " + schema + ".outbox_events FROM PUBLIC"},
		{"foreign schema table read", "GRANT SELECT ON " + foreignSchema + ".secret TO " + role,
			"REVOKE SELECT ON " + foreignSchema + ".secret FROM " + role},
		{"foreign schema column read", "GRANT SELECT (payload) ON " + foreignSchema + ".secret TO " + role,
			"REVOKE SELECT (payload) ON " + foreignSchema + ".secret FROM " + role},
		{"create schema objects", "GRANT CREATE ON SCHEMA " + schema + " TO " + role,
			"REVOKE CREATE ON SCHEMA " + schema + " FROM " + role},
		{"non-inherited privilege escalation membership", "GRANT pg_read_all_data TO " + role + " WITH INHERIT FALSE, SET TRUE",
			"REVOKE pg_read_all_data FROM " + role},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, tc.grant); err != nil {
				t.Fatal(err)
			}
			check(t, false)
			if _, err := admin.Exec(ctx, tc.revoke); err != nil {
				t.Fatal(err)
			}
			check(t, true)
		})
	}
	if _, err := admin.Exec(ctx, "REVOKE SELECT ON "+schema+".admission_sessions FROM "+role); err != nil {
		t.Fatal(err)
	}
	check(t, false) // incomplete catalog reader privilege is also unavailable
}
