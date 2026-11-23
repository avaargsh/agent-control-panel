-- 0015: least-privilege, tenant-bound read identity for original AgentD evidence.
-- The writer/signer remains owner-controlled. Each reader LOGIN is mapped to
-- exactly one tenant; RLS derives scope from authenticated session_user, never
-- from a caller-settable GUC or request field.
BEGIN;

-- This is a dedicated Sandbox-owned database, not a shared application DB.
-- PostgreSQL normally grants TEMPORARY to PUBLIC. Revoke that inherited
-- privilege for all connections; a separate reader LOGIN must also fail
-- validation if an operator later re-grants TEMP directly or through a role.
-- Never run this owner-only migration against a shared database.
DO $
BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END;
$;

DO $
DECLARE
  reader pg_roles%ROWTYPE;
BEGIN
  SELECT * INTO reader FROM pg_roles WHERE rolname='sandbox_agentd_evidence_reader';
  IF NOT FOUND THEN
    CREATE ROLE sandbox_agentd_evidence_reader
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  ELSIF reader.rolcanlogin OR reader.rolsuper OR reader.rolcreatedb OR
        reader.rolcreaterole OR reader.rolreplication OR reader.rolbypassrls OR
        reader.rolinherit THEN
    RAISE EXCEPTION 'sandbox_agentd_evidence_reader role attributes drifted';
  END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS public.sandbox_agentd_evidence_reader_tenants (
  login_role name PRIMARY KEY,
  tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')
);
REVOKE ALL ON public.sandbox_agentd_evidence_reader_tenants FROM PUBLIC;

-- SECURITY DEFINER is deliberately narrow: session_user is the authenticated
-- database LOGIN and cannot be changed by SET ROLE. The function can read only
-- the owner-only login-to-tenant map and returns one tenant string.
CREATE OR REPLACE FUNCTION public.sandbox_agentd_evidence_tenant()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT tenant_id
  FROM public.sandbox_agentd_evidence_reader_tenants
  WHERE login_role = session_user::name
$$;
REVOKE ALL ON FUNCTION public.sandbox_agentd_evidence_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.sandbox_agentd_evidence_tenant()
  TO sandbox_agentd_evidence_reader;

GRANT USAGE ON SCHEMA public TO sandbox_agentd_evidence_reader;
GRANT SELECT ON public.sandbox_agentd_attempts,
                public.sandbox_agentd_terminal_receipts,
                public.sandbox_agentd_inspect_events
  TO sandbox_agentd_evidence_reader;

REVOKE ALL ON public.sandbox_agentd_attempts,
              public.sandbox_agentd_terminal_receipts,
              public.sandbox_agentd_inspect_events
  FROM PUBLIC;

DROP POLICY IF EXISTS agentd_attempt_evidence_reader_tenant
  ON public.sandbox_agentd_attempts;
CREATE POLICY agentd_attempt_evidence_reader_tenant
  ON public.sandbox_agentd_attempts
  FOR SELECT TO sandbox_agentd_evidence_reader
  USING (tenant_id = public.sandbox_agentd_evidence_tenant());

DROP POLICY IF EXISTS agentd_terminal_evidence_reader_tenant
  ON public.sandbox_agentd_terminal_receipts;
CREATE POLICY agentd_terminal_evidence_reader_tenant
  ON public.sandbox_agentd_terminal_receipts
  FOR SELECT TO sandbox_agentd_evidence_reader
  USING (tenant_id = public.sandbox_agentd_evidence_tenant());

DROP POLICY IF EXISTS agentd_inspect_evidence_reader_tenant
  ON public.sandbox_agentd_inspect_events;
CREATE POLICY agentd_inspect_evidence_reader_tenant
  ON public.sandbox_agentd_inspect_events
  FOR SELECT TO sandbox_agentd_evidence_reader
  USING (tenant_id = public.sandbox_agentd_evidence_tenant());

COMMIT;
