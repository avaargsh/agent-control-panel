package agentd

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

var ErrEvidenceReaderUntrusted = errors.New("AgentD evidence reader database identity is unavailable or overprivileged")

// verifyEvidenceReaderLogin rejects owner, migrator, superuser, BYPASSRLS and
// broadly privileged connections before a read endpoint touches source rows.
// Each authenticated LOGIN is mapped to exactly one tenant in an owner-only
// table. RLS derives that tenant from session_user, not a caller-settable GUC.
func verifyEvidenceReaderLogin(ctx context.Context, tx pgx.Tx, expectedTenant string) error {
	if tx == nil || expectedTenant == "" {
		return ErrEvidenceReaderUntrusted
	}
	const check = `
SELECT COALESCE((
  SELECT current_user = session_user
     AND r.rolcanlogin
     AND r.rolinherit
     AND NOT r.rolsuper
     AND NOT r.rolbypassrls
     AND NOT r.rolcreaterole
     AND NOT r.rolcreatedb
     AND NOT r.rolreplication
     AND pg_has_role(r.oid, 'sandbox_agentd_evidence_reader', 'USAGE')
     AND has_schema_privilege(r.oid, 'public', 'USAGE')
     AND NOT has_schema_privilege(r.oid, 'public', 'CREATE')
     AND NOT has_database_privilege(r.oid, current_database(), 'CREATE')
     AND NOT pg_has_role(r.oid, owner_row.relowner, 'MEMBER')
     AND public.sandbox_agentd_evidence_tenant() = $1
     AND NOT has_table_privilege(r.oid, 'public.sandbox_agentd_evidence_reader_tenants', 'SELECT')
     AND NOT EXISTS (
       SELECT 1 FROM pg_auth_members m
       WHERE m.member = r.oid
         AND m.roleid <> (SELECT oid FROM pg_roles WHERE rolname='sandbox_agentd_evidence_reader')
     )
     AND NOT EXISTS (
       SELECT 1 FROM pg_auth_members m
       WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname='sandbox_agentd_evidence_reader')
     )
     AND NOT EXISTS (
       SELECT 1 FROM pg_namespace n
       WHERE n.nspname NOT IN ('pg_catalog','information_schema','public')
         AND n.nspname NOT LIKE 'pg_toast%'
         AND n.nspname NOT LIKE 'pg_temp_%'
         AND has_schema_privilege(r.oid, n.oid, 'USAGE')
     )
     AND NOT EXISTS (
       SELECT 1
       FROM pg_class c
       JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE c.relkind IN ('r','p','v','m','f')
         AND n.nspname NOT IN ('pg_catalog','information_schema')
         AND n.nspname NOT LIKE 'pg_toast%'
         AND n.nspname NOT LIKE 'pg_temp_%'
         AND (
           has_table_privilege(r.oid,c.oid,'SELECT')
           OR has_table_privilege(r.oid,c.oid,'INSERT')
           OR has_table_privilege(r.oid,c.oid,'UPDATE')
           OR has_table_privilege(r.oid,c.oid,'DELETE')
           OR has_table_privilege(r.oid,c.oid,'TRUNCATE')
           OR has_table_privilege(r.oid,c.oid,'REFERENCES')
           OR has_table_privilege(r.oid,c.oid,'TRIGGER')
         )
         AND NOT (
           n.nspname='public'
           AND c.relname IN (
             'sandbox_agentd_attempts',
             'sandbox_agentd_terminal_receipts',
             'sandbox_agentd_inspect_events'
           )
           AND has_table_privilege(r.oid,c.oid,'SELECT')
           AND NOT (
             has_table_privilege(r.oid,c.oid,'INSERT')
             OR has_table_privilege(r.oid,c.oid,'UPDATE')
             OR has_table_privilege(r.oid,c.oid,'DELETE')
             OR has_table_privilege(r.oid,c.oid,'TRUNCATE')
             OR has_table_privilege(r.oid,c.oid,'REFERENCES')
             OR has_table_privilege(r.oid,c.oid,'TRIGGER')
           )
         )
     )
     AND NOT EXISTS (
       SELECT 1
       FROM pg_class c
       JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE c.relkind='S'
         AND n.nspname NOT IN ('pg_catalog','information_schema')
         AND n.nspname NOT LIKE 'pg_toast%'
         AND n.nspname NOT LIKE 'pg_temp_%'
         AND (
           has_sequence_privilege(r.oid,c.oid,'SELECT')
           OR has_sequence_privilege(r.oid,c.oid,'USAGE')
           OR has_sequence_privilege(r.oid,c.oid,'UPDATE')
         )
     )
     AND NOT EXISTS (
       SELECT 1
       FROM pg_proc f
       JOIN pg_namespace n ON n.oid=f.pronamespace
       WHERE f.prosecdef
         AND n.nspname NOT IN ('pg_catalog','information_schema')
         AND n.nspname NOT LIKE 'pg_toast%'
         AND n.nspname NOT LIKE 'pg_temp_%'
         AND has_schema_privilege(r.oid,n.oid,'USAGE')
         AND has_function_privilege(r.oid,f.oid,'EXECUTE')
         AND NOT (
           f.oid=to_regprocedure('public.sandbox_agentd_evidence_tenant()')
           AND f.proowner=owner_row.relowner
           AND f.prorettype='text'::regtype
           AND f.provolatile='s'
           AND f.proconfig @> ARRAY['search_path=pg_catalog, public']
         )
     )
     AND NOT EXISTS (
       SELECT 1
       FROM pg_class c
       WHERE c.oid IN (
         to_regclass('public.sandbox_agentd_attempts'),
         to_regclass('public.sandbox_agentd_terminal_receipts'),
         to_regclass('public.sandbox_agentd_inspect_events')
       )
       AND NOT c.relrowsecurity
     )
  FROM pg_roles r
  CROSS JOIN LATERAL (
    SELECT relowner FROM pg_class
    WHERE oid=to_regclass('public.sandbox_agentd_attempts')
  ) owner_row
  WHERE r.rolname=current_user
), false)`
	var allowed bool
	if err := tx.QueryRow(ctx, check, expectedTenant).Scan(&allowed); err != nil || !allowed {
		return ErrEvidenceReaderUntrusted
	}
	return nil
}
