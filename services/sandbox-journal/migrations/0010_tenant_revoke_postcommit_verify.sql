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

  -- Checking only the two known Writer/Reader groups is insufficient.
  -- A misconfigured DBA can later grant an unrelated inheritable or
  -- SET ROLE-capable group after the local revocation receipt was written.
  -- A revoked principal must have NO remaining role membership at all.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members AS m
    WHERE m.member = p_expected_oid
  ) THEN
    RAISE EXCEPTION 'revoked LOGIN retains an unexpected PostgreSQL role membership'
      USING ERRCODE = '23514';
  END IF;

  -- Likewise, direct ACL grants (including column-level rights) survive
  -- revoking the two runtime group memberships. Inspect ALL source-owned
  -- lease state and governance tables. If the role was dropped, there is
  -- no remaining role OID whose object rights can be exercised.
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles AS r
    CROSS JOIN (
      VALUES
        ('public.sandbox_lease_intents'::regclass),
        ('public.sandbox_lease_intent_events'::regclass),
        ('public.sandbox_lease_db_principals'::regclass),
        ('public.sandbox_lease_login_revocations'::regclass)
    ) AS protected(table_oid)
    WHERE r.oid = p_expected_oid
      AND (
        pg_catalog.has_table_privilege(
          r.oid, protected.table_oid,
          'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        )
        OR pg_catalog.has_any_column_privilege(
          r.oid, protected.table_oid, 'SELECT,INSERT,UPDATE,REFERENCES'
        )
      )
  ) THEN
    RAISE EXCEPTION 'revoked LOGIN retains source-owned lease object privileges'
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
