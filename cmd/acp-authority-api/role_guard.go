package main

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

// verifyAuthorityDatabaseRole is a deployment gate, not a tenant
// authenticator. The mTLS service already binds one tenant out of band.
// Reject shared/migrator credentials even when default_transaction_read_only
// is configured: that session parameter is not an actual privilege boundary.
//
// Inspect the effective LOGIN principal on the live connection and the exact
// relations used by GetExecutionAuthorityInput. No schema ownership, DDL,
// table mutation, extra application-table SELECT or RLS bypass is permitted.
func verifyAuthorityDatabaseRole(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("ACP authority database role unavailable")
	}

	const check = `
WITH actor AS (
    SELECT oid, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication
      FROM pg_catalog.pg_roles
     WHERE rolname = current_user AND current_user = session_user
),
namespace AS (
    SELECT oid, nspowner FROM pg_catalog.pg_namespace
     WHERE nspname = current_schema()
),
required AS (
    SELECT unnest(ARRAY[
        'run_intents', 'admission_tenants', 'admission_projects',
        'admission_principals', 'admission_memberships',
        'admission_releases', 'admission_sessions'
    ]) AS name
)
SELECT COALESCE((
    SELECT NOT (a.rolsuper OR a.rolbypassrls OR a.rolcreaterole
                 OR a.rolcreatedb OR a.rolreplication)
       AND has_schema_privilege(n.oid, 'USAGE')
       AND NOT has_schema_privilege(n.oid, 'CREATE')
       AND NOT pg_has_role(a.oid, n.nspowner, 'MEMBER')
       AND (
           SELECT count(*) = (SELECT count(*) FROM required)
              AND COALESCE(bool_and(
                  c.relkind IN ('r', 'p')
                  AND has_table_privilege(c.oid, 'SELECT')
                  AND NOT has_table_privilege(c.oid,
                      'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                  AND NOT pg_has_role(a.oid, c.relowner, 'MEMBER')
              ), false)
             FROM pg_catalog.pg_class c
            WHERE c.relnamespace = n.oid
              AND c.relname IN (SELECT name FROM required)
       )
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_class c
            WHERE c.relnamespace = n.oid
              AND c.relkind IN ('r','p','v','m','f')
              AND c.relname NOT IN (SELECT name FROM required)
              AND (
                  has_table_privilege(c.oid, 'SELECT')
                  OR has_table_privilege(c.oid,
                      'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
              )
       )
      FROM actor a CROSS JOIN namespace n
), false)
`
	var allowed bool
	if err := pool.QueryRow(ctx, check).Scan(&allowed); err != nil || !allowed {
		return errors.New("ACP authority database role is not least-privilege read-only")
	}
	return nil
}
