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
