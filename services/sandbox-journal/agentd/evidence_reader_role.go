package agentd

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

var ErrEvidenceReaderUntrusted = errors.New("AgentD evidence reader database identity is unavailable or overprivileged")

// Pin the exact 0016 owner-managed SECURITY DEFINER function body.
// Metadata alone cannot detect a rewritten resolver trusting caller GUCs.
// Any legitimate upgrade needs a forward-only migration and matching pin.
const trustedAgentDEvidenceTenantBody = `
    SELECT b.tenant_id
      FROM public.sandbox_agentd_evidence_reader_tenants AS b
      JOIN pg_catalog.pg_roles AS r
        ON r.oid = b.login_oid AND r.rolname = b.login_role
     WHERE r.rolname = session_user
       AND r.rolcanlogin
       AND NOT r.rolsuper
       AND NOT r.rolbypassrls
`

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
     AND EXISTS (
       SELECT 1 FROM pg_roles g
       WHERE g.rolname='sandbox_agentd_evidence_reader'
         AND NOT g.rolcanlogin AND NOT g.rolsuper AND NOT g.rolcreatedb
         AND NOT g.rolcreaterole AND NOT g.rolreplication
         AND NOT g.rolbypassrls AND NOT g.rolinherit
     )
     AND NOT EXISTS (
       SELECT 1 FROM pg_auth_members m
       WHERE m.member=r.oid
         AND m.roleid=(SELECT oid FROM pg_roles WHERE rolname='sandbox_agentd_evidence_reader')
         AND m.admin_option
     )
     AND has_schema_privilege(r.oid, 'public', 'USAGE')
     AND NOT has_schema_privilege(r.oid, 'public', 'CREATE')
     AND NOT has_database_privilege(r.oid, current_database(), 'CREATE')
     AND NOT has_database_privilege(r.oid, current_database(), 'TEMP')
     AND NOT pg_has_role(r.oid, owner_row.relowner, 'MEMBER')
     AND public.sandbox_agentd_evidence_tenant() = $1
     AND EXISTS (
       SELECT 1 FROM pg_catalog.pg_attribute a
       WHERE a.attrelid=to_regclass('public.sandbox_agentd_evidence_reader_tenants')
         AND a.attname='login_oid' AND a.attnotnull AND NOT a.attisdropped
     )
     AND NOT has_table_privilege(r.oid, 'public.sandbox_agentd_evidence_reader_tenants', 'SELECT')
     AND (SELECT relowner FROM pg_class WHERE oid=to_regclass('public.sandbox_agentd_evidence_reader_tenants')) = owner_row.relowner
     AND NOT EXISTS (
       SELECT 1 FROM pg_class c
       WHERE c.oid IN (
         to_regclass('public.sandbox_agentd_terminal_receipts'),
         to_regclass('public.sandbox_agentd_inspect_events')
       )
       AND c.relowner <> owner_row.relowner
     )
     AND (
       SELECT count(*) FROM pg_policies p
       WHERE p.schemaname='public'
         AND (
           (p.tablename='sandbox_agentd_attempts'
             AND p.policyname='agentd_attempt_evidence_reader_tenant')
           OR (p.tablename='sandbox_agentd_terminal_receipts'
             AND p.policyname='agentd_terminal_evidence_reader_tenant')
           OR (p.tablename='sandbox_agentd_inspect_events'
             AND p.policyname='agentd_inspect_evidence_reader_tenant')
         )
         AND p.cmd='SELECT'
         AND p.permissive='PERMISSIVE'
         AND p.roles = ARRAY['sandbox_agentd_evidence_reader'::name]
         -- In PG16 pg_policies.qual reconstructs the original tenant
         -- equality as exactly this expression. LIKE permitted a malicious
         -- in-place ALTER POLICY ... USING (tenant_id=func() OR true).
         -- Reject unexpected expression rewrites and fail closed on
         -- version-dependent deparse drift until separately reviewed.
         AND p.qual='(tenant_id = sandbox_agentd_evidence_tenant())'
     ) = 3
     -- PostgreSQL OR-combines permissive policies. A newly granted
     -- SELECT TO PUBLIC policy would expose foreign-tenant source rows
     -- even while all three expected scoped policies remain installed.
     -- Deny policy drift, rather than merely checking their presence.
     AND NOT EXISTS (
       SELECT 1 FROM pg_policies p
       WHERE p.schemaname='public'
         AND p.tablename IN (
           'sandbox_agentd_attempts',
           'sandbox_agentd_terminal_receipts',
           'sandbox_agentd_inspect_events'
         )
         AND NOT (
           (p.tablename='sandbox_agentd_attempts'
             AND p.policyname='agentd_attempt_evidence_reader_tenant')
           OR (p.tablename='sandbox_agentd_terminal_receipts'
             AND p.policyname='agentd_terminal_evidence_reader_tenant')
           OR (p.tablename='sandbox_agentd_inspect_events'
             AND p.policyname='agentd_inspect_evidence_reader_tenant')
         )
     )
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
         AND (has_schema_privilege(r.oid, n.oid, 'USAGE') OR has_schema_privilege(r.oid, n.oid, 'CREATE'))
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
           AND f.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql')
           AND f.prosrc=$2
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
	if err := tx.QueryRow(ctx, check, expectedTenant, trustedAgentDEvidenceTenantBody).Scan(&allowed); err != nil || !allowed {
		return ErrEvidenceReaderUntrusted
	}
	return nil
}
