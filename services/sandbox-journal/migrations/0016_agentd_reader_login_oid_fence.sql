-- 0016: forward-only authenticated AgentD reader LOGIN/OID fencing.
-- Preserve the prior 0015 bytes and checksum; never rewrite a recorded migration.
-- A reader mapped to a renamed/recreated LOGIN must not gain another tenant.
BEGIN;

ALTER TABLE public.sandbox_agentd_evidence_reader_tenants
    ADD COLUMN IF NOT EXISTS login_oid oid;

-- For an existing owner-managed binding, an absent or unsafe LOGIN cannot
-- silently inherit another principal's identity. Fail the whole migration
-- instead of deleting, bypassing or inventing a mapping.
UPDATE public.sandbox_agentd_evidence_reader_tenants AS b
   SET login_oid = r.oid
  FROM pg_catalog.pg_roles AS r
 WHERE b.login_role = r.rolname
   AND r.rolcanlogin
   AND NOT r.rolsuper
   AND NOT r.rolbypassrls;
ALTER TABLE public.sandbox_agentd_evidence_reader_tenants
    ALTER COLUMN login_oid SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS sandbox_agentd_reader_login_oid_uniq
    ON public.sandbox_agentd_evidence_reader_tenants (login_oid);

-- Keep the same function identity used by the three existing RLS policies.
-- Only its owner-managed lookup gets stronger; app.tenant_id is never trusted.
CREATE OR REPLACE FUNCTION public.sandbox_agentd_evidence_tenant()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT b.tenant_id
      FROM public.sandbox_agentd_evidence_reader_tenants AS b
      JOIN pg_catalog.pg_roles AS r
        ON r.oid = b.login_oid AND r.rolname = b.login_role
     WHERE r.rolname = session_user
       AND r.rolcanlogin
       AND NOT r.rolsuper
       AND NOT r.rolbypassrls
$$;
REVOKE ALL ON FUNCTION public.sandbox_agentd_evidence_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.sandbox_agentd_evidence_tenant()
    TO sandbox_agentd_evidence_reader;
REVOKE ALL ON public.sandbox_agentd_evidence_reader_tenants
    FROM PUBLIC, sandbox_agentd_evidence_reader;

COMMIT;
