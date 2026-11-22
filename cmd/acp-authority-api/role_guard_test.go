package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	if _, err := admin.Exec(ctx, "INSERT INTO "+foreignSchema+".secret VALUES (1, 'foreign-schema-canary')"); err != nil {
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
		"GRANT USAGE ON SCHEMA " + foreignSchema + " TO " + role,
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
	var databaseName string
	if err := admin.QueryRow(ctx, "SELECT current_database()").Scan(&databaseName); err != nil {
		t.Fatal(err)
	}
	databaseIdent := pgx.Identifier{databaseName}.Sanitize()
	ddlProbeSchema := "acp_role_ddl_probe_" + suffix

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
		{"create in foreign schema", "GRANT CREATE ON SCHEMA " + foreignSchema + " TO " + role,
			"REVOKE CREATE ON SCHEMA " + foreignSchema + " FROM " + role},
		{"create new database schema", "GRANT CREATE ON DATABASE " + databaseIdent + " TO " + role,
			"REVOKE CREATE ON DATABASE " + databaseIdent + " FROM " + role},
		{"non-inherited privilege escalation membership", "GRANT pg_read_all_data TO " + role + " WITH INHERIT FALSE, SET TRUE",
			"REVOKE pg_read_all_data FROM " + role},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, tc.grant); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(tc.name, "foreign schema") {
				// Actual independently authenticated reader proves the grant
				// is usable, not merely present in pg_catalog metadata.
				var payload string
				if err := reader.QueryRow(ctx, "SELECT payload FROM "+foreignSchema+".secret").Scan(&payload); err != nil || payload != "foreign-schema-canary" {
					t.Fatalf("foreign schema grant was not effectively readable: payload=%q err=%v", payload, err)
				}
			}
			// Verify the unexpectedly granted DDL is executable by the
			// independently authenticated reader, not merely listed in ACLs.
			switch tc.name {
			case "create in foreign schema":
				if _, err := reader.Exec(ctx, "CREATE TABLE "+foreignSchema+".role_probe (id integer)"); err != nil {
					t.Fatalf("foreign schema CREATE grant was not effective: %v", err)
				}
				if _, err := reader.Exec(ctx, "DROP TABLE "+foreignSchema+".role_probe"); err != nil {
					t.Fatal(err)
				}
			case "create new database schema":
				if _, err := reader.Exec(ctx, "CREATE SCHEMA "+ddlProbeSchema); err != nil {
					t.Fatalf("database CREATE grant was not effective: %v", err)
				}
				if _, err := reader.Exec(ctx, "DROP SCHEMA "+ddlProbeSchema); err != nil {
					t.Fatal(err)
				}
			}
			check(t, false)
			if _, err := admin.Exec(ctx, tc.revoke); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(tc.name, "foreign schema") {
				var payload string
				err := reader.QueryRow(ctx, "SELECT payload FROM "+foreignSchema+".secret").Scan(&payload)
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
					t.Fatalf("foreign schema read must deny with SQLSTATE 42501 after revoke: err=%v", err)
				}
			}
			check(t, true)
		})
	}
	// PostgreSQL sequences use a distinct privilege model (USAGE/SELECT/UPDATE),
	// not table SELECT/UPDATE or column grants. Assert both configured and
	// unrelated application schemas with the independently authenticated LOGIN.
	for _, seqSchema := range []string{schema, foreignSchema} {
		seq := seqSchema + ".authority_gate_probe_seq"
		if _, err := admin.Exec(ctx, "CREATE SEQUENCE "+seq); err != nil {
			t.Fatal(err)
		}
		for _, privilege := range []string{"USAGE", "SELECT", "UPDATE"} {
			t.Run("sequence/"+seqSchema+"/"+privilege, func(t *testing.T) {
				if _, err := admin.Exec(ctx, "GRANT "+privilege+" ON SEQUENCE "+seq+" TO "+role); err != nil {
					t.Fatal(err)
				}
				readSequence := func() error {
					var value int64
					if privilege == "SELECT" {
						return reader.QueryRow(ctx, "SELECT last_value FROM "+seq).Scan(&value)
					}
					return reader.QueryRow(ctx, "SELECT nextval($1::regclass)", seq).Scan(&value)
				}
				if err := readSequence(); err != nil {
					t.Fatalf("sequence privilege was not effective as reader: %v", err)
				}
				check(t, false)
				if _, err := admin.Exec(ctx, "REVOKE "+privilege+" ON SEQUENCE "+seq+" FROM "+role); err != nil {
					t.Fatal(err)
				}
				var pgErr *pgconn.PgError
				if err := readSequence(); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
					t.Fatalf("sequence privilege revoke must deny with SQLSTATE 42501: %v", err)
				}
				check(t, true)
			})
		}
	}

	// SECURITY DEFINER functions execute as their owner and are callable by
	// PUBLIC by default. A read-only LOGIN with EXECUTE can therefore disclose
	// data it cannot SELECT directly. Probe both the current schema and an
	// unrelated application schema using real PostgreSQL role credentials.
	for _, functionSchema := range []string{schema, foreignSchema} {
		t.Run("security-definer/"+functionSchema, func(t *testing.T) {
			functionName := functionSchema + ".authority_privilege_probe"
			create := "CREATE FUNCTION " + functionName + "() RETURNS text " +
				"LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog " +
				"AS $ SELECT payload FROM " + foreignSchema + ".secret WHERE id=1 $"
			if _, err := admin.Exec(ctx, create); err != nil {
				t.Fatal(err)
			}
			defer admin.Exec(context.Background(), "DROP FUNCTION "+functionName+"()")
			call := func() (string, error) {
				var value string
				err := reader.QueryRow(ctx, "SELECT "+functionName+"()").Scan(&value)
				return value, err
			}
			// This is the default PUBLIC EXECUTE grant on newly defined
			// functions, not an explicit grant to the tested principal.
			if value, err := call(); err != nil || value != "foreign-schema-canary" {
				t.Fatalf("default PUBLIC EXECUTE did not expose owner-only data: value=%q err=%v", value, err)
			}
			check(t, false)
			if _, err := admin.Exec(ctx, "REVOKE EXECUTE ON FUNCTION "+functionName+"() FROM PUBLIC"); err != nil {
				t.Fatal(err)
			}
			assertDenied := func() {
				t.Helper()
				_, err := call()
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
					t.Fatalf("revoked SECURITY DEFINER EXECUTE should return 42501: %v", err)
				}
			}
			assertDenied()
			check(t, true)

			// Explicit EXECUTE grant can re-open the same bypass after
			// PUBLIC was revoked. Verify actual execution, denial, recovery.
			if _, err := admin.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+functionName+"() TO "+role); err != nil {
				t.Fatal(err)
			}
			if value, err := call(); err != nil || value != "foreign-schema-canary" {
				t.Fatalf("explicit SECURITY DEFINER grant did not expose owner-only data: value=%q err=%v", value, err)
			}
			check(t, false)
			if _, err := admin.Exec(ctx, "REVOKE EXECUTE ON FUNCTION "+functionName+"() FROM "+role); err != nil {
				t.Fatal(err)
			}
			assertDenied()
			check(t, true)
		})
	}

	if _, err := admin.Exec(ctx, "REVOKE SELECT ON "+schema+".admission_sessions FROM "+role); err != nil {
		t.Fatal(err)
	}
	check(t, false) // incomplete catalog reader privilege is also unavailable
}
