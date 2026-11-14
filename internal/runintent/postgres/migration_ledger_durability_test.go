package postgres

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

// The migration ledger must survive a PostgreSQL crash. A checksum alone
// cannot prove that its storage is persistent after an operator-side ALTER.
func TestMigrationLedgerRejectsUnloggedStorage(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "ALTER TABLE schema_migrations SET UNLOGGED"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("unlogged schema_migrations was accepted: %v", err)
	}
}

func TestMigrationLedgerRejectsConstraintDrift(t *testing.T) {
	cases := []struct {
		name       string
		statements []string
	}{
		{"missing version PK", []string{
			"ALTER TABLE schema_migrations DROP CONSTRAINT schema_migrations_pkey",
		}},
		{"missing migration name uniqueness", []string{
			"ALTER TABLE schema_migrations DROP CONSTRAINT schema_migrations_name_key",
		}},
		{"same name weakened checksum CHECK", []string{
			"ALTER TABLE schema_migrations DROP CONSTRAINT schema_migrations_checksum_check",
			"ALTER TABLE schema_migrations ADD CONSTRAINT schema_migrations_checksum_check CHECK (TRUE)",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx := context.Background()
			for _, statement := range tc.statements {
				if _, err := pool.Exec(ctx, statement); err != nil {
					t.Fatalf("inject ledger drift %s: %v", tc.name, err)
				}
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("migration ledger constraint drift accepted (%s): %v", tc.name, err)
			}
		})
	}
}

func TestMigrationLedgerRejectsPublicGrants(t *testing.T) {
	for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"} {
		t.Run(privilege, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx := context.Background()
			if _, err := pool.Exec(ctx, "GRANT "+privilege+" ON TABLE schema_migrations TO PUBLIC"); err != nil {
				t.Fatalf("inject PUBLIC %s: %v", privilege, err)
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("PUBLIC %s on checksum ledger accepted: %v", privilege, err)
			}
		})
	}
}

func TestMigrationLedgerRejectsExplicitNonOwnerRoleGrants(t *testing.T) {
	for _, privilege := range []string{"SELECT", "UPDATE"} {
		t.Run(privilege, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx := context.Background()
			role := "acp_ledger_probe_" + strconv.FormatInt(time.Now().UnixNano(), 10)
			if _, err := pool.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
				t.Fatalf("create non-owner role: %v", err)
			}
			t.Cleanup(func() {
				if _, err := pool.Exec(context.Background(), "DROP OWNED BY "+role); err != nil {
					t.Errorf("drop non-owner grants: %v", err)
					return
				}
				if _, err := pool.Exec(context.Background(), "DROP ROLE "+role); err != nil {
					t.Errorf("drop non-owner role: %v", err)
				}
			})
			if _, err := pool.Exec(ctx, "GRANT "+privilege+" ON TABLE schema_migrations TO "+role); err != nil {
				t.Fatalf("inject non-owner ledger privilege: %v", err)
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("non-owner %s on migration ledger was accepted: %v", privilege, err)
			}
		})
	}
}

// Column-level privileges are stored in pg_attribute.attacl, not the table's
// pg_class.relacl. A non-owner must not read or rewrite migration checksums
// through a column grant even when table-level ACLs are owner-only.
func TestMigrationLedgerRejectsColumnLevelGrants(t *testing.T) {
	cases := []struct {
		name      string
		privilege string
		public    bool
	}{
		{"named role SELECT checksum", "SELECT (checksum)", false},
		{"named role UPDATE checksum", "UPDATE (checksum)", false},
		{"PUBLIC SELECT checksum", "SELECT (checksum)", true},
		{"PUBLIC UPDATE checksum", "UPDATE (checksum)", true},
		{"named role SELECT version", "SELECT (version)", false},
		{"named role UPDATE applied_at", "UPDATE (applied_at)", false},
		{"PUBLIC REFERENCES version", "REFERENCES (version)", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx := context.Background()
			grantee := "PUBLIC"
			if !tc.public {
				grantee = "acp_ledger_column_probe_" + strconv.FormatInt(time.Now().UnixNano(), 10)
				if _, err := pool.Exec(ctx, "CREATE ROLE "+grantee+" NOLOGIN"); err != nil {
					t.Fatalf("create non-owner role: %v", err)
				}
				t.Cleanup(func() {
					if _, err := pool.Exec(context.Background(), "DROP OWNED BY "+grantee); err != nil {
						t.Errorf("drop non-owner grants: %v", err)
						return
					}
					if _, err := pool.Exec(context.Background(), "DROP ROLE "+grantee); err != nil {
						t.Errorf("drop non-owner role: %v", err)
					}
				})
			}
			if _, err := pool.Exec(ctx, "GRANT "+tc.privilege+" ON schema_migrations TO "+grantee); err != nil {
				t.Fatalf("inject %s grant: %v", tc.name, err)
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("column-level non-owner grant accepted (%s): %v", tc.name, err)
			}
		})
	}
}

// A table owner may explicitly grant itself a column permission. This must
// not be confused with a PUBLIC or another role's grant in attacl.
func TestMigrationLedgerAllowsOwnerColumnGrants(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	var isOwner bool
	if err := pool.QueryRow(ctx, `SELECT c.relowner = (SELECT oid FROM pg_roles WHERE rolname=current_user)
		FROM pg_class c WHERE c.oid=to_regclass('schema_migrations')`).Scan(&isOwner); err != nil {
		t.Fatalf("inspect ledger owner: %v", err)
	}
	if !isOwner {
		t.Fatal("test connection must be ledger owner")
	}
	if _, err := pool.Exec(ctx, "GRANT SELECT (checksum), UPDATE (name) ON schema_migrations TO CURRENT_USER"); err != nil {
		t.Fatalf("grant owner-only column privileges: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("owner-only column grants rejected: %v", err)
	}
}
