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
	// A sequence is not a table/view. USAGE and UPDATE can both grant
	// nextval() mutation without any table DML privilege.
	foreignSequence := pgx.Identifier{foreignSchema, "privilege_probe_seq"}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SEQUENCE "+foreignSequence); err != nil {
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
	// A dedicated login may have no direct SELECT on a sensitive relation
	// yet read it through a SECURITY DEFINER function. PostgreSQL grants
	// EXECUTE on new functions to PUBLIC by default; schema USAGE suffices
	// for this otherwise underprivileged LOGIN to invoke the function.
	t.Run("callable SECURITY DEFINER cannot bypass readonly role fence", func(t *testing.T) {
		probe := pgx.Identifier{foreignSchema, "reader_privilege_probe"}.Sanitize()
		if _, err := admin.Exec(ctx, "CREATE FUNCTION "+probe+
			"() RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT payload FROM "+
			pgx.Identifier{foreignSchema, "secret"}.Sanitize()+" LIMIT 1'"); err != nil {
			t.Fatal(err)
		}
		defer admin.Exec(context.Background(), "DROP FUNCTION "+probe+"()")
		var leaked string
		if err := reader.QueryRow(ctx, "SELECT "+probe+"()").Scan(&leaked); err != nil || leaked != "foreign-schema-canary" {
			t.Fatalf("probe did not exercise actual SECURITY DEFINER privilege escalation: value=%q err=%v", leaked, err)
		}
		// The role has no direct SELECT on foreignSchema.secret. A callable
		// definer function must still be rejected at startup.
		check(t, false)
		// Test effective access, not the mere existence of a routine:
		// removing PUBLIC EXECUTE must restore this dedicated reader.
		if _, err := admin.Exec(ctx, "REVOKE EXECUTE ON FUNCTION "+probe+"() FROM PUBLIC"); err != nil {
			t.Fatal(err)
		}
		check(t, true)
		// A direct grant must fail again even without PUBLIC EXECUTE.
		if _, err := admin.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+probe+"() TO "+role); err != nil {
			t.Fatal(err)
		}
		check(t, false)
		if _, err := admin.Exec(ctx, "REVOKE EXECUTE ON FUNCTION "+probe+"() FROM "+role); err != nil {
			t.Fatal(err)
		}
		check(t, true)
	})
	check(t, true)
	t.Run("foreign sequence grants bypass table-only reader guard", func(t *testing.T) {
		for _, right := range []string{"USAGE", "UPDATE", "SELECT"} {
			t.Run(right, func(t *testing.T) {
				if _, err := admin.Exec(ctx, "GRANT "+right+" ON SEQUENCE "+foreignSequence+" TO "+role); err != nil {
					t.Fatal(err)
				}
				query := "SELECT nextval($1::regclass)"
				if right == "SELECT" {
					query = "SELECT last_value FROM " + foreignSequence
				}
				var value int64
				var err error
				if right == "SELECT" {
					err = reader.QueryRow(ctx, query).Scan(&value)
				} else {
					err = reader.QueryRow(ctx, query, foreignSequence).Scan(&value)
				}
				if err != nil || value < 1 {
					t.Fatalf("actual independently authenticated reader cannot exercise %s sequence privilege: value=%d err=%v", right, value, err)
				}
				// Any effective foreign sequence right is outside the
				// seven-table authority reader's read-only contract.
				check(t, false)
				if _, err := admin.Exec(ctx, "REVOKE "+right+" ON SEQUENCE "+foreignSequence+" FROM "+role); err != nil {
					t.Fatal(err)
				}
				check(t, true)
				if right == "SELECT" {
					err = reader.QueryRow(ctx, query).Scan(&value)
				} else {
					err = reader.QueryRow(ctx, query, foreignSequence).Scan(&value)
				}
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
					t.Fatalf("sequence %s must fail with SQLSTATE 42501 after revoke: err=%v", right, err)
				}
			})
		}
	})
	// Effective PostgreSQL sequence privileges include grants to PUBLIC,
	// not just direct grants to this LOGIN. Enforce the same deny/revoke
	// behavior for a PUBLIC-granted side-effectful nextval operation.
	t.Run("public sequence usage is not read-only authority", func(t *testing.T) {
		if _, err := admin.Exec(ctx, "GRANT USAGE ON SEQUENCE "+foreignSequence+" TO PUBLIC"); err != nil {
			t.Fatal(err)
		}
		var advanced int64
		if err := reader.QueryRow(ctx, "SELECT nextval($1::regclass)", foreignSequence).Scan(&advanced); err != nil || advanced < 1 {
			t.Fatalf("actual PUBLIC-granted sequence mutation not observed: value=%d err=%v", advanced, err)
		}
		check(t, false)
		if _, err := admin.Exec(ctx, "REVOKE USAGE ON SEQUENCE "+foreignSequence+" FROM PUBLIC"); err != nil {
			t.Fatal(err)
		}
		check(t, true)
		var denied *pgconn.PgError
		err := reader.QueryRow(ctx, "SELECT nextval($1::regclass)", foreignSequence).Scan(&advanced)
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatalf("PUBLIC sequence usage must deny after revocation: %v", err)
		}
	})
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
	if _, err := admin.Exec(ctx, "REVOKE SELECT ON "+schema+".admission_sessions FROM "+role); err != nil {
		t.Fatal(err)
	}
	check(t, false) // incomplete catalog reader privilege is also unavailable
}
