package authoritycutover

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type RoleMode string

const (
	CoordinatorRole RoleMode = "coordinator"
	ObserverRole    RoleMode = "observer"
)

var ErrRoleDrift = errors.New("cutover database role drift or unavailable")

// VerifyPostgresRole checks the authenticated backend's current catalog
// snapshot. It is an explicit probe, not a Store admission hook, DCL fence,
// schema attestation or proof that privileges cannot change after the query.
// The expected login is supplied by trusted deployment configuration.
func VerifyPostgresRole(ctx context.Context, conn *pgx.Conn, login string, mode RoleMode) error {
	if conn == nil || login == "" || ctx.Err() != nil {
		return ErrRoleDrift
	}
	var group string
	switch mode {
	case CoordinatorRole:
		group = "acp_cutover_coordinator"
	case ObserverRole:
		group = "acp_cutover_observer"
	default:
		return ErrRoleDrift
	}
	var valid bool
	if err := conn.QueryRow(ctx, roleProbeSQL, login, group, mode == CoordinatorRole).Scan(&valid); err != nil {
		return fmt.Errorf("%w: %w", ErrRoleDrift, err)
	}
	if !valid || ctx.Err() != nil {
		return ErrRoleDrift
	}
	return nil
}

// Check effective table/column privileges, including inherited grants, and
// explicitly reject PUBLIC ACLs even when they add no effective privilege
// to the expected login. Qualified catalog functions avoid search_path
// substitution. This deliberately rejects other reachable role memberships.
const roleProbeSQL = `
WITH expected(relname, cols, inserts, updates) AS (
 VALUES
 ('acp_authority_cutover_state',
  ARRAY['id','generation','revision','phase','change_id','manifest_digest','operator_id']::text[],
  ARRAY[]::text[], ARRAY['generation','revision','phase','change_id','manifest_digest','operator_id']::text[]),
 ('acp_authority_cutover_changes',
  ARRAY['change_id','manifest_digest','operator_id','start_generation']::text[],
  ARRAY['change_id','manifest_digest','operator_id','start_generation']::text[], ARRAY[]::text[]),
 ('acp_authority_cutover_transitions',
  ARRAY['revision','generation','phase','change_id','manifest_digest','operator_id','start_generation']::text[],
  ARRAY['revision','generation','phase','change_id','manifest_digest','operator_id']::text[], ARRAY[]::text[])
), target AS (
 SELECT e.*, c.oid, c.relacl, c.relowner, c.relkind, c.relpersistence, c.relrowsecurity
 FROM expected e
 JOIN pg_catalog.pg_namespace n ON n.nspname='public'
 JOIN pg_catalog.pg_class c ON c.relnamespace=n.oid AND c.relname=e.relname
), principals AS (
 SELECT oid, rolname, rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
 FROM pg_catalog.pg_roles
 WHERE rolname IN ($1,$2,'acp_cutover_schema_owner')
)
SELECT session_user::text=$1 AND current_user::text=$1
 AND (SELECT count(*) FROM principals)=3
 AND NOT EXISTS (
  SELECT 1 FROM principals
  WHERE rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls
   OR rolcanlogin<>(rolname=$1)
 )
 AND EXISTS (
  SELECT 1 FROM principals WHERE rolname=$2
   AND pg_catalog.pg_has_role(oid,'USAGE')
 )
 AND NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles r
  WHERE r.rolname NOT IN ($1,$2) AND pg_catalog.pg_has_role(r.oid,'MEMBER')
 )
 AND NOT pg_catalog.has_database_privilege(pg_catalog.current_database(),'TEMP')
 AND NOT pg_catalog.has_database_privilege(pg_catalog.current_database(),'CREATE')
 AND pg_catalog.has_schema_privilege('public','USAGE')
 AND NOT pg_catalog.has_schema_privilege('public','CREATE')
 AND (SELECT count(*) FROM target)=3
 AND NOT EXISTS (
  SELECT 1 FROM target t
  WHERE t.relkind<>'r' OR t.relpersistence<>'p' OR t.relrowsecurity
   OR t.relowner<>(SELECT oid FROM principals WHERE rolname='acp_cutover_schema_owner')
   OR NOT pg_catalog.has_table_privilege(t.oid,'SELECT')
   OR pg_catalog.has_table_privilege(t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR pg_catalog.has_table_privilege(t.oid,'SELECT WITH GRANT OPTION')
   OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(t.relacl) a WHERE a.grantee=0)
   OR (SELECT count(*) FROM pg_catalog.pg_attribute a
       WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped)<>pg_catalog.cardinality(t.cols)
   OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_attribute a
    WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
     AND (NOT (a.attname::text=ANY(t.cols))
      OR NOT pg_catalog.has_column_privilege(t.oid,a.attnum,'SELECT')
      OR pg_catalog.has_column_privilege(t.oid,a.attnum,'INSERT')<>($3 AND a.attname::text=ANY(t.inserts))
      OR pg_catalog.has_column_privilege(t.oid,a.attnum,'UPDATE')<>($3 AND a.attname::text=ANY(t.updates))
      OR pg_catalog.has_column_privilege(t.oid,a.attnum,'REFERENCES')
      OR pg_catalog.has_column_privilege(t.oid,a.attnum,'SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION')
      OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(a.attacl) p WHERE p.grantee=0))
   )
 )`
