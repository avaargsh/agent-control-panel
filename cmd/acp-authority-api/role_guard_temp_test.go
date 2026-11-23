package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This uses a disposable PostgreSQL 16 database, not the shared PGTEST_DSN
// database: revoking the default PUBLIC TEMP grant must not affect concurrent
// package tests. The reader authenticates as an independent LOGIN role.
//
// PostgreSQL searches a session's temporary namespace before ordinary
// search_path schemas for unqualified relation names. A role permitted to
// CREATE TEMP can shadow run_intents, while an ACL guard that checks only
// the configured schema's tables may still approve that role.
func TestAuthorityDatabaseRoleRejectsTempShadow(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	root, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close(context.Background())

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	database := pgx.Identifier{"acp_auth_temp_" + suffix}.Sanitize()
	databaseName := "acp_auth_temp_" + suffix
	role := "acp_auth_reader_" + suffix
	if _, err := root.Exec(ctx, "CREATE DATABASE "+database); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := root.Exec(context.Background(), "DROP DATABASE "+database+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated PostgreSQL test database: %v", err)
		}
		if _, err := root.Exec(context.Background(), "DROP ROLE "+role); err != nil {
			t.Errorf("drop isolated PostgreSQL reader role: %v", err)
		}
	}()

	adminCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminCfg.Database = databaseName
	admin, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	const schema = "acp_reader_scope"
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = databaseName
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	owner, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := runpg.Migrate(ctx, owner); err != nil {
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
	grants := []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT SELECT ON " + schema + "." +
			"run_intents, " + schema + ".admission_tenants, " +
			schema + ".admission_projects, " + schema + ".admission_principals, " +
			schema + ".admission_memberships, " + schema + ".admission_releases, " +
			schema + ".admission_sessions TO " + role,
	}
	for _, query := range grants {
		if _, err := admin.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	readerCfg := cfg.Copy()
	readerCfg.ConnConfig.User = role
	readerCfg.ConnConfig.Password = password
	readerCfg.MaxConns = 1 // guard and shadow query use the same authenticated session
	reader, err := pgxpool.NewWithConfig(ctx, readerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	var hasTemp bool
	if err := reader.QueryRow(ctx, "SELECT has_database_privilege(current_database(), 'TEMP')").Scan(&hasTemp); err != nil {
		t.Fatal(err)
	}
	if !hasTemp {
		t.Fatal("PostgreSQL default PUBLIC TEMP privilege unavailable: test precondition violated")
	}
	if _, err := reader.Exec(ctx, "CREATE TEMP TABLE run_intents (probe text)"); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Exec(ctx, "INSERT INTO pg_temp.run_intents VALUES ('forged-run-authority')"); err != nil {
		t.Fatal(err)
	}
	var got, currentSchema string
	if err := reader.QueryRow(ctx, "SELECT probe FROM run_intents").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if err := reader.QueryRow(ctx, "SELECT current_schema()").Scan(&currentSchema); err != nil {
		t.Fatal(err)
	}
	if got != "forged-run-authority" || currentSchema != schema {
		t.Fatalf("shadow exploit precondition failed: got=%q current_schema=%q", got, currentSchema)
	}
	if err := verifyAuthorityDatabaseRole(ctx, reader); err == nil {
		t.Fatal("guard accepted TEMP-enabled LOGIN with attacker-controlled run_intents shadow")
	}

	if _, err := reader.Exec(ctx, "DROP TABLE pg_temp.run_intents"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "REVOKE TEMPORARY ON DATABASE "+database+" FROM PUBLIC"); err != nil {
		t.Fatal(err)
	}
	if err := reader.QueryRow(ctx, "SELECT has_database_privilege(current_database(), 'TEMP')").Scan(&hasTemp); err != nil {
		t.Fatal(err)
	}
	if hasTemp {
		t.Fatal("reader retained effective TEMP privilege after PUBLIC revocation")
	}
	if err := verifyAuthorityDatabaseRole(ctx, reader); err != nil {
		t.Fatalf("dedicated reader with TEMP revoked was incorrectly denied: %v", err)
	}

	if _, err := admin.Exec(ctx, "GRANT TEMPORARY ON DATABASE "+database+" TO "+role); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuthorityDatabaseRole(ctx, reader); err == nil {
		t.Fatal("direct TEMP grant must not restore authority reader access")
	}
	if _, err := admin.Exec(ctx, "REVOKE TEMPORARY ON DATABASE "+database+" FROM "+role); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuthorityDatabaseRole(ctx, reader); err != nil {
		t.Fatalf("reader did not recover after explicit TEMP grant revocation: %v", err)
	}
}
