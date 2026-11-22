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
       -- CREATE at database scope permits making an entirely new schema;
       -- checking grants on the configured schema alone is insufficient.
       AND NOT has_database_privilege(current_database(), 'CREATE')
       -- A foreign application schema may grant DDL without granting
       -- SELECT or other privileges on any existing relations. Reject
       -- effective CREATE anywhere outside PostgreSQL system namespaces.
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_namespace s
            WHERE s.nspname NOT IN ('pg_catalog', 'information_schema')
              AND s.nspname NOT LIKE 'pg_toast%'
              AND s.nspname NOT LIKE 'pg_temp_%'
              AND has_schema_privilege(s.oid, 'CREATE')
       )
       AND NOT pg_has_role(a.oid, n.nspowner, 'MEMBER')
       -- Even NOINHERIT memberships may permit SET ROLE to a privileged
       -- identity after startup. This dedicated service login must belong
       -- to no other database role, including group/NOLOGIN roles.
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=a.oid
       )
       AND (
           SELECT count(*) = (SELECT count(*) FROM required)
              AND COALESCE(bool_and(
                  c.relkind IN ('r', 'p')
                  AND has_table_privilege(c.oid, 'SELECT')
                  AND NOT has_table_privilege(c.oid,
                      'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                  -- Table privileges do not include column-only GRANTs.
                  AND NOT has_any_column_privilege(c.oid, 'INSERT,UPDATE,REFERENCES')
                  AND NOT pg_has_role(a.oid, c.relowner, 'MEMBER')
              ), false)
             FROM pg_catalog.pg_class c
            WHERE c.relnamespace = n.oid
              AND c.relname IN (SELECT name FROM required)
       )
       -- Reject effective grants on application relations outside the
       -- configured catalog schema as well. Checking current_schema()
       -- alone lets a read-only login keep unrelated cross-schema access.
       -- Built-in catalog and ephemeral PostgreSQL namespaces are not
       -- business data schemas and have their own system ACL semantics.
       AND NOT EXISTS (
           SELECT 1
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
            WHERE s.oid <> n.oid
              AND s.nspname NOT IN ('pg_catalog', 'information_schema')
              AND s.nspname NOT LIKE 'pg_toast%'
              AND s.nspname NOT LIKE 'pg_temp_%'
              AND c.relkind IN ('r','p','v','m','f')
              AND (
                  has_table_privilege(c.oid, 'SELECT')
                  OR has_table_privilege(c.oid,
                      'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                  OR has_any_column_privilege(c.oid, 'SELECT,INSERT,UPDATE,REFERENCES')
              )
       )
       -- Sequence USAGE/SELECT/UPDATE are not relation or column ACLs.
       -- A reader with nextval/setval or sequence-reading access can mutate
       -- or inspect independently scoped state even with no table grants.
       -- Deny effective sequence privileges in every application schema,
       -- including the configured catalog schema.
       AND NOT EXISTS (
           SELECT 1
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace s ON s.oid = c.relnamespace
            WHERE c.relkind = 'S'
              AND s.nspname NOT IN ('pg_catalog', 'information_schema')
              AND s.nspname NOT LIKE 'pg_toast%'
              AND s.nspname NOT LIKE 'pg_temp_%'
              AND (
                  has_sequence_privilege(c.oid, 'USAGE')
                  OR has_sequence_privilege(c.oid, 'SELECT')
                  OR has_sequence_privilege(c.oid, 'UPDATE')
              )
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
                  OR has_any_column_privilege(c.oid, 'SELECT,INSERT,UPDATE,REFERENCES')
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
