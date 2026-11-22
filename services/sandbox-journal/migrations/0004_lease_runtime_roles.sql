-- DBA/operator-only, additive role grants for the independent Sandbox DB.
-- Run after 0001-0003. Never run on ACP's RunIntent database or through
-- a runtime credential. NOLOGIN group roles receive no secrets or owner power.
-- An independently provisioned LOGIN may be granted exactly one group role.
BEGIN;

DO $$
DECLARE
  role_name text;
  role_oid oid;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    'acp_sandbox_lease_writer',
    'acp_sandbox_lease_reader'
  ] LOOP
    SELECT oid INTO role_oid FROM pg_roles WHERE rolname = role_name;
    IF role_oid IS NULL THEN
      EXECUTE format(
        'CREATE ROLE %I NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
        role_name
      );
      SELECT oid INTO role_oid FROM pg_roles WHERE rolname = role_name;
    END IF;
    -- A preexisting privileged or owner/member role is untrusted. Do not
    -- "repair" it by granting more access and call the migration successful.
    IF EXISTS (
      SELECT 1 FROM pg_roles
      WHERE oid = role_oid AND (
        rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole
        OR rolreplication OR rolbypassrls
      )
    ) OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member = role_oid)
      OR EXISTS (SELECT 1 FROM pg_class WHERE relowner = role_oid) THEN
      RAISE EXCEPTION 'unsafe preexisting Sandbox lease runtime role: %', role_name;
    END IF;
  END LOOP;
END;
$$;

-- Roles are exclusive to this Sandbox-owned database. In particular, they
-- must never inherit rights on the adjacent CommandJournal tables.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public
  FROM acp_sandbox_lease_writer, acp_sandbox_lease_reader;

GRANT USAGE ON SCHEMA public
  TO acp_sandbox_lease_writer, acp_sandbox_lease_reader;
REVOKE CREATE ON SCHEMA public
  FROM acp_sandbox_lease_writer, acp_sandbox_lease_reader;

GRANT SELECT, INSERT ON TABLE public.sandbox_lease_intents
  TO acp_sandbox_lease_writer;
GRANT UPDATE (state, generation, updated_at)
  ON TABLE public.sandbox_lease_intents
  TO acp_sandbox_lease_writer;
GRANT SELECT, INSERT ON TABLE public.sandbox_lease_intent_events
  TO acp_sandbox_lease_writer;

GRANT SELECT ON TABLE
  public.sandbox_lease_intents,
  public.sandbox_lease_intent_events
  TO acp_sandbox_lease_reader;

-- PostgreSQL 15+ normally revokes CREATE ON SCHEMA public from PUBLIC.
-- If an older/bespoke database regrants it, fail closed; granting a
-- dedicated role cannot override a PUBLIC grant.
DO $$
BEGIN
  IF has_schema_privilege('acp_sandbox_lease_writer','public','CREATE')
     OR has_schema_privilege('acp_sandbox_lease_reader','public','CREATE') THEN
    RAISE EXCEPTION 'public schema CREATE granted; fix Sandbox DB privilege policy first';
  END IF;
END;
$$;

COMMIT;
