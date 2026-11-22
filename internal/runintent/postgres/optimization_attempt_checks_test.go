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
