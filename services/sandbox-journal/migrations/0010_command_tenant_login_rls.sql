-- Independent Sandbox PostgreSQL database ONLY, after 0009 tenant revocation migration and 0008 role-OID fence.
-- CommandJournal is still pre-Permit PERMIT_UNAVAILABLE only: no dispatch,
-- AgentD process, provider allocation, receipt of execution or Guard Permit.
-- Reuse the DBA-owned, OID-fenced authenticated LOGIN -> tenant binding.
-- Never authenticate tenants with a caller-supplied tenant_id/GUC.
BEGIN;

LOCK TABLE public.sandbox_journal_commands, public.sandbox_journal_outbox
  IN SHARE ROW EXCLUSIVE MODE;

DO $$
DECLARE
  role_name text;
  role_oid oid;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    'acp_sandbox_command_writer',
    'acp_sandbox_command_reader'
  ] LOOP
    SELECT oid INTO role_oid FROM pg_catalog.pg_roles WHERE rolname = role_name;
    IF role_oid IS NULL THEN
      EXECUTE format(
        'CREATE ROLE %I NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
        role_name
      );
      SELECT oid INTO role_oid FROM pg_catalog.pg_roles WHERE rolname = role_name;
    END IF;
    IF EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles
      WHERE oid = role_oid AND (
        rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole
        OR rolreplication OR rolbypassrls
      )
    ) OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member = role_oid)
      OR EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE relowner = role_oid)
    THEN
      RAISE EXCEPTION 'unsafe preexisting Sandbox command role: %', role_name;
    END IF;
  END LOOP;
END;
$$;

-- Separate Command principal groups from lease writer/reader groups.
-- The command writer can only append and inspect pre-Permit facts; it
-- cannot UPDATE/DELETE/TRUNCATE, disable append-only triggers or own schema.
REVOKE ALL PRIVILEGES ON TABLE
  public.sandbox_journal_commands, public.sandbox_journal_outbox
  FROM acp_sandbox_command_writer, acp_sandbox_command_reader;

GRANT USAGE ON SCHEMA public
  TO acp_sandbox_command_writer, acp_sandbox_command_reader;
REVOKE CREATE ON SCHEMA public
  FROM acp_sandbox_command_writer, acp_sandbox_command_reader;

GRANT SELECT, INSERT ON TABLE
  public.sandbox_journal_commands, public.sandbox_journal_outbox
  TO acp_sandbox_command_writer;
GRANT SELECT ON TABLE
  public.sandbox_journal_commands, public.sandbox_journal_outbox
  TO acp_sandbox_command_reader;

-- Historically named for leases, this is the sole owner-controlled Sandbox
-- DB LOGIN -> tenant authority. 0008 verifies the LOGIN's exact role OID.
-- Do not fork an independently mutable Command tenant registry.
GRANT EXECUTE ON FUNCTION public.sandbox_bound_lease_tenant()
  TO acp_sandbox_command_writer, acp_sandbox_command_reader;

ALTER TABLE public.sandbox_journal_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sandbox_journal_outbox ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sandbox_command_tenant_select
  ON public.sandbox_journal_commands;
CREATE POLICY sandbox_command_tenant_select
  ON public.sandbox_journal_commands FOR SELECT
  TO acp_sandbox_command_writer, acp_sandbox_command_reader
  USING (tenant_id = public.sandbox_bound_lease_tenant());

DROP POLICY IF EXISTS sandbox_command_tenant_insert
  ON public.sandbox_journal_commands;
CREATE POLICY sandbox_command_tenant_insert
  ON public.sandbox_journal_commands FOR INSERT
  TO acp_sandbox_command_writer
  WITH CHECK (tenant_id = public.sandbox_bound_lease_tenant());

DROP POLICY IF EXISTS sandbox_command_outbox_tenant_select
  ON public.sandbox_journal_outbox;
CREATE POLICY sandbox_command_outbox_tenant_select
  ON public.sandbox_journal_outbox FOR SELECT
  TO acp_sandbox_command_writer, acp_sandbox_command_reader
  USING (tenant_id = public.sandbox_bound_lease_tenant());

DROP POLICY IF EXISTS sandbox_command_outbox_tenant_insert
  ON public.sandbox_journal_outbox;
CREATE POLICY sandbox_command_outbox_tenant_insert
  ON public.sandbox_journal_outbox FOR INSERT
  TO acp_sandbox_command_writer
  WITH CHECK (tenant_id = public.sandbox_bound_lease_tenant());

DO $$
BEGIN
  IF has_schema_privilege('acp_sandbox_command_writer', 'public', 'CREATE')
     OR has_schema_privilege('acp_sandbox_command_reader', 'public', 'CREATE')
     OR has_table_privilege('acp_sandbox_command_reader',
                           'public.sandbox_journal_commands', 'INSERT,UPDATE,DELETE,TRUNCATE')
     OR has_table_privilege('acp_sandbox_command_reader',
                           'public.sandbox_journal_outbox', 'INSERT,UPDATE,DELETE,TRUNCATE')
     OR has_table_privilege('acp_sandbox_command_writer',
                           'public.sandbox_journal_commands', 'UPDATE,DELETE,TRUNCATE')
     OR has_table_privilege('acp_sandbox_command_writer',
                           'public.sandbox_journal_outbox', 'UPDATE,DELETE,TRUNCATE')
  THEN
    RAISE EXCEPTION 'unsafe effective privileges on Sandbox Command roles';
  END IF;
END;
$$;

-- Version 0009 predates Command roles. Extend its owner-only, OID-fenced
-- revocation procedure without changing the already-applied 0009 migration.
-- The same atomic NOLOGIN + session eviction now also removes both Command
-- group memberships; otherwise a later DBA re-enrolment could accidentally
-- restore implicit Command privileges. No runtime principal may execute it.
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
  EXECUTE format('REVOKE acp_sandbox_command_writer FROM %I', p_login);
  EXECUTE format('REVOKE acp_sandbox_command_reader FROM %I', p_login);

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
  FROM PUBLIC, acp_sandbox_lease_writer, acp_sandbox_lease_reader,
       acp_sandbox_command_writer, acp_sandbox_command_reader;

COMMIT;
