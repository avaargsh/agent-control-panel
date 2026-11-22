package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The version-13 checksum proves what was initially applied. It must not
// accept a later privileged actor replacing any guard with same-name CHECK(TRUE).
func TestOptimizationAttemptMigrationRejectsWeakenedCheckPredicates(t *testing.T) {
	cases := []struct {
		name       string
		constraint string
	}{
		{"consumption consistency", "optimization_attempt_consumption_consistency"},
		{"expiry lifetime", "optimization_attempt_lifetime"},
		{"nonce shape", "optimization_verification_attempts_verification_nonce_check"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx := context.Background()
			// Constraint names are fixed by checked-in v13 migration, never
			// supplied by a user; this is a disposable, privileged test schema.
			if _, err := pool.Exec(ctx, "ALTER TABLE optimization_verification_attempts DROP CONSTRAINT "+tc.constraint); err != nil {
				t.Fatalf("drop v13 check: %v", err)
			}
			if _, err := pool.Exec(ctx, "ALTER TABLE optimization_verification_attempts ADD CONSTRAINT "+tc.constraint+" CHECK (TRUE)"); err != nil {
				t.Fatalf("inject weak same-name CHECK: %v", err)
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("same-name weakened v13 CHECK accepted: name=%s err=%v", tc.constraint, err)
			}
		})
	}
}

// NOT NULL and defaults are just as security-relevant as CHECK expressions.
// A nullable expiry bypasses SQL CHECK via UNKNOWN, and a changed default
// can cause issued/consumed records to be rejected or forged unexpectedly.
func TestOptimizationAttemptMigrationRejectsColumnMetadataDrift(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"nullable expiry", "ALTER TABLE optimization_verification_attempts ALTER COLUMN expires_at DROP NOT NULL"},
		{"nullable tenant", "ALTER TABLE optimization_verification_attempts ALTER COLUMN tenant_id DROP NOT NULL"},
		{"missing issue-time default", "ALTER TABLE optimization_verification_attempts ALTER COLUMN issued_at DROP DEFAULT"},
		{"forged consume-time default", "ALTER TABLE optimization_verification_attempts ALTER COLUMN consumed_at SET DEFAULT clock_timestamp()"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx := context.Background()
			if _, err := pool.Exec(ctx, tc.sql); err != nil {
				t.Fatalf("inject v13 column drift: %v", err)
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("weak v13 column metadata accepted: case=%q err=%v", tc.name, err)
			}
		})
	}
}

// RLS and ACL checks must not implicitly trust a new table or trigger-function
// owner: owner privileges are not represented as an unexpected non-owner GRANT.
// A privileged accidental ownership transfer is schema drift and must block
// the migration gate before the untrusted role can edit the security boundary.
func TestOptimizationAttemptMigrationRejectsOwnershipDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		object string
	}{
		{"attempt table", "TABLE optimization_verification_attempts"},
		{"mutation trigger function", "FUNCTION reject_optimization_attempt_mutation()"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx := context.Background()
			role := fmt.Sprintf("opt_wrong_owner_%d", time.Now().UnixNano())
			roleID := pgx.Identifier{role}.Sanitize()
			var migrator string
			if err := pool.QueryRow(ctx, "SELECT current_user").Scan(&migrator); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, "CREATE ROLE "+roleID+" NOLOGIN NOBYPASSRLS"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				// Restore object ownership before dropping the disposable role.
				stmt := "ALTER " + tc.object + " OWNER TO " + pgx.Identifier{migrator}.Sanitize()
				if _, err := pool.Exec(context.Background(), stmt); err != nil {
					t.Errorf("restore reviewed migration owner: %v", err)
				}
				if _, err := pool.Exec(context.Background(), "DROP ROLE "+roleID); err != nil {
					t.Errorf("drop disposable recipient role: %v", err)
				}
			})
			if _, err := pool.Exec(ctx, "ALTER "+tc.object+" OWNER TO "+roleID); err != nil {
				t.Fatalf("inject migration object owner drift: %v", err)
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("%s owner transfer accepted as valid v13 security boundary: %v", tc.name, err)
			}
		})
	}
}

// The schema_migrations owner is a catalog entry, not an independent trust
// root. A privileged out-of-band change can transfer the ledger, protected
// table and trigger function together, preserving pairwise owner equality.
// A fresh trusted migration login must still refuse that coordinated drift.
func TestOptimizationAttemptMigrationRejectsCoordinatedOwnerTransfer(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	var migrator, session string
	if err := pool.QueryRow(ctx, "SELECT current_user, session_user").Scan(&migrator, &session); err != nil {
		t.Fatal(err)
	}
	if migrator != session {
		t.Fatalf("fixture must have a stable authenticated migrator: current=%q session=%q", migrator, session)
	}
	role := fmt.Sprintf("opt_coordinated_owner_%d", time.Now().UnixNano())
	roleID := pgx.Identifier{role}.Sanitize()
	migratorID := pgx.Identifier{migrator}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE ROLE "+roleID+" NOLOGIN NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	objects := []string{
		"TABLE schema_migrations",
		"TABLE optimization_verification_attempts",
		"FUNCTION reject_optimization_attempt_mutation()",
	}
	t.Cleanup(func() {
		for i := len(objects) - 1; i >= 0; i-- {
			if _, err := pool.Exec(context.Background(), "ALTER "+objects[i]+" OWNER TO "+migratorID); err != nil {
				t.Errorf("restore trusted %s owner: %v", objects[i], err)
			}
		}
		if _, err := pool.Exec(context.Background(), "DROP ROLE "+roleID); err != nil {
			t.Errorf("drop disposable coordinated-owner role: %v", err)
		}
	})
	for _, object := range objects {
		if _, err := pool.Exec(ctx, "ALTER "+object+" OWNER TO "+roleID); err != nil {
			t.Fatalf("inject coordinated owner drift on %s: %v", object, err)
		}
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("untrusted coordinated ledger/table/function ownership was accepted: %v", err)
	}
}
