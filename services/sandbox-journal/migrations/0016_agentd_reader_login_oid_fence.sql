-- 0016: forward-only authenticated AgentD reader LOGIN/OID fencing.
-- Preserve the prior 0015 bytes and checksum; never rewrite a recorded migration.
-- A reader mapped to a renamed/recreated LOGIN must not gain another tenant.
BEGIN;

ALTER TABLE public.sandbox_agentd_evidence_reader_tenants
    ADD COLUMN IF NOT EXISTS login_oid oid;

-- 0015 stored only a LOGIN name, not its original role OID. Looking up
-- pg_roles NOW cannot prove that an old login was not dropped and recreated
-- under the same name. Never auto-backfill that untrusted name-only mapping.
--
-- A trusted owner must stop source readers, revoke legacy bindings under
-- the original 0015 schema, run 0016, then explicitly re-enroll each LOGIN
-- with its freshly verified OID and tenant. A failed upgrade rolls back the
-- ADD COLUMN as well; no partially upgraded authorization is acceptable.
-- On an already-upgraded schema, non-null OIDs support safe idempotent replay.
DO $agentd_reader_upgrade$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM public.sandbox_agentd_evidence_reader_tenants
         WHERE login_oid IS NULL
    ) THEN
        RAISE EXCEPTION
            'AgentD 0016 blocked: unverifiable legacy LOGIN binding; owner must revoke and re-enroll'
            USING ERRCODE = '23514';
    END IF;
END;
$agentd_reader_upgrade$;
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
