-- Owner-only Sandbox database migration AFTER 0008. This candidate
-- revokes a single exact PostgreSQL LOGIN/OID tenant identity and evicts
-- existing sessions. It is not executable by the Sandbox runtime roles.
-- This is DB-level controlled revocation, not instant distributed authz.
BEGIN;

CREATE TABLE IF NOT EXISTS public.sandbox_lease_login_revocations (
  revocation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  login_name name NOT NULL,
  login_role_oid oid NOT NULL,
  tenant_id text NOT NULL,
  terminated_sessions integer NOT NULL CHECK (terminated_sessions >= 0),
  revoked_by name NOT NULL,
  revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (login_role_oid)
);
REVOKE ALL ON TABLE public.sandbox_lease_login_revocations FROM PUBLIC;
REVOKE ALL ON TABLE public.sandbox_lease_login_revocations
  FROM acp_sandbox_lease_writer, acp_sandbox_lease_reader;

CREATE OR REPLACE FUNCTION public.sandbox_deny_lease_revocation_history_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'sandbox lease-login revocation facts are append-only'
    USING ERRCODE = '23514';
END;
$$;

DROP TRIGGER IF EXISTS sandbox_lease_login_revocations_no_update_delete
  ON public.sandbox_lease_login_revocations;
CREATE TRIGGER sandbox_lease_login_revocations_no_update_delete
BEFORE UPDATE OR DELETE ON public.sandbox_lease_login_revocations
FOR EACH ROW EXECUTE FUNCTION public.sandbox_deny_lease_revocation_history_mutation();

DROP TRIGGER IF EXISTS sandbox_lease_login_revocations_no_truncate
  ON public.sandbox_lease_login_revocations;
CREATE TRIGGER sandbox_lease_login_revocations_no_truncate
BEFORE TRUNCATE ON public.sandbox_lease_login_revocations
FOR EACH STATEMENT EXECUTE FUNCTION public.sandbox_deny_lease_revocation_history_mutation();

-- Run only as the authorized database migration/revocation principal.
-- It needs ALTER ROLE/REVOKE and pg_terminate_backend privileges. If any
-- operation fails, the transaction rolls back; the caller MUST retain its
-- external fail-closed gate and cannot claim revocation succeeded.
CREATE OR REPLACE FUNCTION public.sandbox_revoke_lease_login(
  p_login name, p_expected_oid oid
)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_tenant text;
  v_pid integer;
  v_terminated integer := 0;
  v_operator name := session_user::name;
BEGIN
  IF p_login IS NULL OR p_expected_oid IS NULL THEN
    RAISE EXCEPTION 'exact login name and role OID are required'
      USING ERRCODE = '23514';
  END IF;

  SELECT p.tenant_id INTO v_tenant
  FROM public.sandbox_lease_db_principals AS p
  JOIN pg_catalog.pg_roles AS r
    ON r.rolname = p.login_name AND r.oid = p.login_role_oid
  WHERE p.login_name = p_login AND p.login_role_oid = p_expected_oid
    AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
  FOR UPDATE OF p;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'stale or missing principal; refusing unscoped revocation'
      USING ERRCODE = '23514';
  END IF;

  -- All identifiers are quoted. No SQL text or wildcard tenant predicates
  -- come from the caller. NOLOGIN stops fresh login after transaction commit.
  EXECUTE format('ALTER ROLE %I NOLOGIN', p_login);
  EXECUTE format('REVOKE acp_sandbox_lease_writer FROM %I', p_login);
  EXECUTE format('REVOKE acp_sandbox_lease_reader FROM %I', p_login);

  DELETE FROM public.sandbox_lease_db_principals
  WHERE login_name = p_login AND login_role_oid = p_expected_oid;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'principal mapping concurrently changed; refusing revocation'
      USING ERRCODE = '23514';
  END IF;

  -- Existing REPEATABLE READ snapshots can still see a deleted mapping.
  -- Terminate all real authenticated LOGIN sessions, even those currently
  -- SET ROLE to some other role. PostgreSQL 16 timeout verifies exit rather
  -- than only accepting a termination signal.
  FOR v_pid IN
    SELECT a.pid FROM pg_catalog.pg_stat_activity AS a
    WHERE a.usesysid = p_expected_oid AND a.pid <> pg_backend_pid()
  LOOP
    IF NOT pg_catalog.pg_terminate_backend(v_pid, 2000) THEN
      RAISE EXCEPTION 'could not terminate tenant LOGIN backend %', v_pid
        USING ERRCODE = '55000';
    END IF;
    v_terminated := v_terminated + 1;
  END LOOP;

  INSERT INTO public.sandbox_lease_login_revocations
    (login_name, login_role_oid, tenant_id, terminated_sessions, revoked_by)
  VALUES (p_login, p_expected_oid, v_tenant, v_terminated, v_operator);

  RETURN v_terminated;
END;
$$;
REVOKE ALL ON FUNCTION public.sandbox_revoke_lease_login(name, oid)
  FROM PUBLIC, acp_sandbox_lease_writer, acp_sandbox_lease_reader;

COMMIT;
