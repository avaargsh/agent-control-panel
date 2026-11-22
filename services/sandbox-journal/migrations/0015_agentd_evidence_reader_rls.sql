-- 0015: least-privilege, tenant-scoped read identity for original AgentD evidence.
-- The writer/signer remains owner-controlled. This role can only SELECT the
-- three original source tables, and only rows bound to app.tenant_id.
BEGIN;

DO $$
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
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

DROP POLICY IF EXISTS agentd_terminal_evidence_reader_tenant
  ON public.sandbox_agentd_terminal_receipts;
CREATE POLICY agentd_terminal_evidence_reader_tenant
  ON public.sandbox_agentd_terminal_receipts
  FOR SELECT TO sandbox_agentd_evidence_reader
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

DROP POLICY IF EXISTS agentd_inspect_evidence_reader_tenant
  ON public.sandbox_agentd_inspect_events;
CREATE POLICY agentd_inspect_evidence_reader_tenant
  ON public.sandbox_agentd_inspect_events
  FOR SELECT TO sandbox_agentd_evidence_reader
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

COMMIT;
