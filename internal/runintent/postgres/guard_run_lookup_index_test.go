package postgres

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Guard resolves an authenticated tenant+Run selector before reading its
// original immutable RunIntent. This must be bounded by a tenant-first,
// ACCEPTED-only index as history grows; it must NOT make the key unique,
// because duplicate accepted bindings must still fail closed.
func TestGuardAcceptedRunLookupHasTenantScopedNonUniquePartialIndex(t *testing.T) {
	_, pool := testRepository(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var indexed bool
	err := pool.QueryRow(ctx, `
SELECT count(*)=1
  FROM pg_index i
  JOIN pg_class idx ON idx.oid=i.indexrelid
 WHERE i.indrelid='run_intents'::regclass
   AND idx.relname='run_intents_guard_accepted_runtime_lookup'
   AND i.indisvalid AND i.indisready
   AND NOT i.indisunique
   AND i.indnkeyatts=2 AND i.indnatts=4
   AND i.indexprs IS NULL
   AND pg_get_expr(i.indpred,i.indrelid,false) = '(status = ''ACCEPTED''::text)'
   AND (
     SELECT array_agg(a.attname::text ORDER BY k.ordinality)
       FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum,ordinality)
       JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
   )=ARRAY['tenant_id','runtime_run_id','id','request_digest']::text[]
`).Scan(&indexed)
	if err != nil {
		t.Fatalf("inspect actual PostgreSQL Guard Run lookup index: %v", err)
	}
	if !indexed {
		t.Fatal("missing exact tenant-scoped nonunique ACCEPTED-only Guard Run lookup index; full-table Run selector is not a scalable authority path")
	}
}

func TestGuardAcceptedRunLookupMigrationUpgradesV13WithoutMutatingHistory(t *testing.T) {
	_, pool := testRepository(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Simulate a checksum-valid v13 installation, without modifying any
	// historical SQL bytes; the v14 index and ledger row are absent.
	if _, err := pool.Exec(ctx, "DROP INDEX run_intents_guard_accepted_runtime_lookup"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version=14"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("forward-only v13-to-v14 upgrade denied: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("reapplying v14 migration is not idempotent: %v", err)
	}
	var present bool
	if err := pool.QueryRow(ctx, `SELECT count(*)=1 FROM schema_migrations
		WHERE version=14 AND name='0014_guard_accepted_run_lookup.sql'`).Scan(&present); err != nil || !present {
		t.Fatalf("v14 checksum ledger not atomically recorded: %v present=%t", err, present)
	}
}

func TestGuardAcceptedRunLookupMigrationRejectsIndexDrift(t *testing.T) {
	for _, tc := range []struct {
		name, definition string
	}{
		{"broadened predicate", `CREATE INDEX run_intents_guard_accepted_runtime_lookup
			ON run_intents (tenant_id,runtime_run_id) INCLUDE (id,request_digest)
			WHERE status IN ('ACCEPTED','PENDING')`},
		{"unsafe uniqueness", `CREATE UNIQUE INDEX run_intents_guard_accepted_runtime_lookup
			ON run_intents (tenant_id,runtime_run_id) INCLUDE (id,request_digest)
			WHERE status='ACCEPTED'`},
		{"reordered tenant scope", `CREATE INDEX run_intents_guard_accepted_runtime_lookup
			ON run_intents (runtime_run_id,tenant_id) INCLUDE (id,request_digest)
			WHERE status='ACCEPTED'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			if _, err := pool.Exec(ctx, "DROP INDEX run_intents_guard_accepted_runtime_lookup"); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, tc.definition); err != nil {
				t.Fatal(err)
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("v14 accepted unsafe index drift: %v", err)
			}
		})
	}
}
