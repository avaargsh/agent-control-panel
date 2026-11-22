package postgres

import (
	"context"
	"errors"
	"testing"
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
