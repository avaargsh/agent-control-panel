-- Independent Sandbox-owned PostgreSQL database ONLY; additive after 0006.
-- Tenant isolation requires a distinct authenticated database LOGIN per tenant.
-- The DBA controls immutable LOGIN->tenant binding, not a caller-provided
-- tenant_id parameter or a spoofable SET LOCAL custom GUC. No live credentials.
BEGIN;

LOCK TABLE public.sandbox_lease_intents, public.sandbox_lease_intent_events
  IN SHARE ROW EXCLUSIVE MODE;

-- Owned by migration principal, never by Sandbox application credentials.
CREATE TABLE IF NOT EXISTS public.sandbox_lease_db_principals (
  login_name name PRIMARY KEY,
  tenant_id text NOT NULL
    CHECK (length(tenant_id) BETWEEN 1 AND 128
      AND tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  created_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON TABLE public.sandbox_lease_db_principals FROM PUBLIC;
REVOKE ALL ON TABLE public.sandbox_lease_db_principals
  FROM acp_sandbox_lease_writer, acp_sandbox_lease_reader;

-- A SECURITY DEFINER function reads the DBA-owned binding table, but uses
-- SESSION_USER (the authenticated LOGIN), not CURRENT_USER, which would
-- become the function owner during SECURITY DEFINER execution and also
-- changes when a runtime caller executes SET ROLE.
CREATE OR REPLACE FUNCTION public.sandbox_bound_lease_tenant()
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT p.tenant_id
  FROM public.sandbox_lease_db_principals AS p
  JOIN pg_catalog.pg_roles AS r
    ON r.rolname = p.login_name
  WHERE p.login_name = session_user::name
    AND r.rolcanlogin
    AND NOT r.rolsuper
    AND NOT r.rolbypassrls
  LIMIT 1
$$;
REVOKE ALL ON FUNCTION public.sandbox_bound_lease_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.sandbox_bound_lease_tenant()
  TO acp_sandbox_lease_writer, acp_sandbox_lease_reader;

-- Table owners and superusers can bypass ordinary RLS. Therefore migration
-- principals MUST NOT be used by the Sandbox service; verified non-owner
-- tenant logins receive permissions only through the NOLOGIN groups from 0004.
ALTER TABLE public.sandbox_lease_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sandbox_lease_intent_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sandbox_intents_tenant_read
  ON public.sandbox_lease_intents;
CREATE POLICY sandbox_intents_tenant_read
  ON public.sandbox_lease_intents
  FOR SELECT TO acp_sandbox_lease_writer, acp_sandbox_lease_reader
  USING (tenant_id = public.sandbox_bound_lease_tenant());

DROP POLICY IF EXISTS sandbox_intents_tenant_insert
  ON public.sandbox_lease_intents;
CREATE POLICY sandbox_intents_tenant_insert
  ON public.sandbox_lease_intents
  FOR INSERT TO acp_sandbox_lease_writer
  WITH CHECK (tenant_id = public.sandbox_bound_lease_tenant());

DROP POLICY IF EXISTS sandbox_intents_tenant_update
  ON public.sandbox_lease_intents;
CREATE POLICY sandbox_intents_tenant_update
  ON public.sandbox_lease_intents
  FOR UPDATE TO acp_sandbox_lease_writer
  USING (tenant_id = public.sandbox_bound_lease_tenant())
  WITH CHECK (tenant_id = public.sandbox_bound_lease_tenant());

DROP POLICY IF EXISTS sandbox_events_tenant_read
  ON public.sandbox_lease_intent_events;
CREATE POLICY sandbox_events_tenant_read
  ON public.sandbox_lease_intent_events
  FOR SELECT TO acp_sandbox_lease_writer, acp_sandbox_lease_reader
  USING (tenant_id = public.sandbox_bound_lease_tenant());

DROP POLICY IF EXISTS sandbox_events_tenant_insert
  ON public.sandbox_lease_intent_events;
CREATE POLICY sandbox_events_tenant_insert
  ON public.sandbox_lease_intent_events
  FOR INSERT TO acp_sandbox_lease_writer
  WITH CHECK (tenant_id = public.sandbox_bound_lease_tenant());

COMMIT;
