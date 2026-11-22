-- 0016: bind AgentD evidence reader authorization to authenticated PostgreSQL
-- LOGIN + immutable role OID, not caller-controlled app.tenant_id.
-- Owner-only provisioning; the source tables remain append-only/no-dispatch.
BEGIN;

CREATE TABLE IF NOT EXISTS public.sandbox_agentd_reader_login_bindings (
    login_name name PRIMARY KEY,
    login_oid oid NOT NULL UNIQUE,
    tenant_id text NOT NULL CHECK (tenant_id <> '' AND length(tenant_id) <= 255)
);
REVOKE ALL ON public.sandbox_agentd_reader_login_bindings
    FROM PUBLIC, sandbox_agentd_evidence_reader;

-- SECURITY DEFINER only reads a protected owner-managed binding table.
-- session_user is the authenticated LOGIN and is unaffected by SET ROLE or
-- custom session GUC changes. Matching both name and OID fences role reuse.
CREATE OR REPLACE FUNCTION public.sandbox_agentd_authenticated_reader_tenant()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT b.tenant_id
      FROM public.sandbox_agentd_reader_login_bindings AS b
      JOIN pg_catalog.pg_roles AS r
        ON r.oid = b.login_oid
       AND r.rolname = b.login_name
     WHERE r.rolname = session_user
       AND r.rolcanlogin
       AND NOT r.rolsuper
       AND NOT r.rolbypassrls
$$;
REVOKE ALL ON FUNCTION public.sandbox_agentd_authenticated_reader_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.sandbox_agentd_authenticated_reader_tenant()
    TO sandbox_agentd_evidence_reader;

-- Replace every untrusted custom-GUC selector with the same authoritative
-- owner-managed binding. An unregistered or renamed LOGIN sees no rows.
DROP POLICY IF EXISTS agentd_attempt_evidence_reader_tenant
    ON public.sandbox_agentd_attempts;
CREATE POLICY agentd_attempt_evidence_reader_tenant
    ON public.sandbox_agentd_attempts
    FOR SELECT TO sandbox_agentd_evidence_reader
    USING (tenant_id = public.sandbox_agentd_authenticated_reader_tenant());

DROP POLICY IF EXISTS agentd_terminal_evidence_reader_tenant
    ON public.sandbox_agentd_terminal_receipts;
CREATE POLICY agentd_terminal_evidence_reader_tenant
    ON public.sandbox_agentd_terminal_receipts
    FOR SELECT TO sandbox_agentd_evidence_reader
    USING (tenant_id = public.sandbox_agentd_authenticated_reader_tenant());

DROP POLICY IF EXISTS agentd_inspect_evidence_reader_tenant
    ON public.sandbox_agentd_inspect_events;
CREATE POLICY agentd_inspect_evidence_reader_tenant
    ON public.sandbox_agentd_inspect_events
    FOR SELECT TO sandbox_agentd_evidence_reader
    USING (tenant_id = public.sandbox_agentd_authenticated_reader_tenant());

COMMIT;
