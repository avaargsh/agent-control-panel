-- Independent Sandbox PostgreSQL database ONLY, after 0008 tenant role-OID fence.
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
COMMIT;
