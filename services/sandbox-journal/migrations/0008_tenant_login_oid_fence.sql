-- Additive, owner-only Sandbox database migration after 0007.
-- An authenticated PostgreSQL LOGIN name is reusable after DROP ROLE.
-- Pin the actual role OID to stop recreated names inheriting old tenant data.
BEGIN;

LOCK TABLE public.sandbox_lease_db_principals IN SHARE ROW EXCLUSIVE MODE;

-- Historical bindings cannot be verified against a deleted login's original
-- OID. Leave existing entries NULL (DENIED) until a trusted DBA explicitly
-- deletes and recreates each binding after checking the actual role identity.
-- Never automatically backfill or silently refresh a preexisting binding.
ALTER TABLE public.sandbox_lease_db_principals
  ADD COLUMN IF NOT EXISTS login_role_oid oid;

CREATE OR REPLACE FUNCTION public.sandbox_pin_lease_login_oid()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actual_role_oid oid;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'tenant-login binding is immutable; delete and re-enroll after DBA review'
      USING ERRCODE = '23514';
  END IF;

  SELECT r.oid INTO actual_role_oid
  FROM pg_catalog.pg_roles AS r
  WHERE r.rolname = NEW.login_name
    AND r.rolcanlogin
    AND NOT r.rolsuper
    AND NOT r.rolbypassrls;

  IF actual_role_oid IS NULL THEN
    RAISE EXCEPTION 'tenant-login binding requires a real unprivileged LOGIN'
      USING ERRCODE = '23514';
  END IF;
  -- The owner, not a caller-supplied value, is the authority for role identity.
  NEW.login_role_oid := actual_role_oid;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.sandbox_pin_lease_login_oid() FROM PUBLIC;

DROP TRIGGER IF EXISTS sandbox_pin_lease_login_oid_on_insert
  ON public.sandbox_lease_db_principals;
CREATE TRIGGER sandbox_pin_lease_login_oid_on_insert
BEFORE INSERT OR UPDATE ON public.sandbox_lease_db_principals
FOR EACH ROW EXECUTE FUNCTION public.sandbox_pin_lease_login_oid();

CREATE OR REPLACE FUNCTION public.sandbox_bound_lease_tenant()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT p.tenant_id
  FROM public.sandbox_lease_db_principals AS p
  JOIN pg_catalog.pg_roles AS r
    ON r.rolname = p.login_name
    AND r.oid = p.login_role_oid
  WHERE p.login_name = session_user::name
    AND p.login_role_oid IS NOT NULL
    AND r.rolcanlogin
    AND NOT r.rolsuper
    AND NOT r.rolbypassrls
  LIMIT 1
$$;
REVOKE ALL ON FUNCTION public.sandbox_bound_lease_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.sandbox_bound_lease_tenant()
  TO acp_sandbox_lease_writer, acp_sandbox_lease_reader;

COMMIT;
