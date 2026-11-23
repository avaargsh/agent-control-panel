package postgres

import (
	"context"
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
