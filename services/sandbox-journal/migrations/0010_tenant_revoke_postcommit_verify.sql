-- Independent Sandbox PostgreSQL database, additive after 0009.
-- Read-only, owner-authorized verification of the *committed* revocation
-- state. MUST be called on a separate connection AFTER the revoker commits.
-- It does not enforce transaction boundaries or gate remote Guard/AgentD.
BEGIN;

CREATE OR REPLACE FUNCTION public.sandbox_verify_lease_login_revocation(
  p_login name, p_expected_oid oid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF p_login IS NULL OR p_expected_oid IS NULL THEN
    RAISE EXCEPTION 'revocation verification requires an exact LOGIN and role OID'
      USING ERRCODE = '23514';
  END IF;

  -- A DB owner can insert a fake receipt. This check only proves presence
  -- of the source-owned local fact, never cryptographic attestation.
  IF NOT EXISTS (
    SELECT 1 FROM public.sandbox_lease_login_revocations AS f
    WHERE f.login_name = p_login AND f.login_role_oid = p_expected_oid
  ) THEN
    RAISE EXCEPTION 'revocation has no committed exact-OID local receipt'
      USING ERRCODE = '23514';
  END IF;

  -- A newly created LOGIN with the same name is a different identity.
  -- Do not claim the old revocation covers the replacement generation.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS r
    WHERE r.rolname = p_login AND r.oid <> p_expected_oid
  ) THEN
    RAISE EXCEPTION 'LOGIN name was reused after revocation'
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS r
    WHERE r.oid = p_expected_oid AND (
      r.rolname <> p_login OR r.rolcanlogin OR r.rolsuper
      OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb
      OR r.rolreplication
    )
  ) THEN
    RAISE EXCEPTION 'revoked role has LOGIN, escalated privileges or changed name'
      USING ERRCODE = '23514';
  END IF;

  -- MEMBER includes indirect memberships. Revocation must not be
  -- verified if either writer/reader role was re-granted to this identity.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS r
    WHERE r.oid = p_expected_oid AND (
      pg_catalog.pg_has_role(
        r.oid, 'acp_sandbox_lease_writer'::regrole, 'MEMBER'
      ) OR pg_catalog.pg_has_role(
        r.oid, 'acp_sandbox_lease_reader'::regrole, 'MEMBER'
      )
    )
  ) THEN
    RAISE EXCEPTION 'revoked role retains Sandbox lease role membership'
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.sandbox_lease_db_principals AS p
    WHERE p.login_name = p_login OR p.login_role_oid = p_expected_oid
  ) THEN
    RAISE EXCEPTION 'revoked LOGIN still has tenant binding'
      USING ERRCODE = '23514';
  END IF;

  -- Fresh pg_stat_activity observation must see no real authenticated
  -- backend, even if that connection executed SET ROLE after login.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_stat_activity AS a
    WHERE a.usesysid = p_expected_oid
  ) THEN
    RAISE EXCEPTION 'revoked LOGIN still has authenticated backend'
      USING ERRCODE = '55000';
  END IF;

  RETURN TRUE;
END;
$$;

-- Runtime Writer/Reader logins must not query the operator verification
-- contract or enumerate privileged proof. The DBA runs this separately.
REVOKE ALL ON FUNCTION public.sandbox_verify_lease_login_revocation(name, oid)
  FROM PUBLIC, acp_sandbox_lease_writer, acp_sandbox_lease_reader;

COMMIT;
