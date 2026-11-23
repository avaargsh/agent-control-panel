-- Independent Sandbox Service database ONLY; additive migration after 0004_lease_runtime_roles.sql.
-- The existing command journal records only terminal PERMIT_UNAVAILABLE facts.
-- No Guard Permit, agent execution or provider resource is created by this DDL.
BEGIN;

-- Prevent races between history inspection and installing append-only DML
-- barriers. This is a source-owned migration, never an ACP RunIntent change.
LOCK TABLE sandbox_journal_commands, sandbox_journal_outbox IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM sandbox_journal_commands AS c
    LEFT JOIN sandbox_journal_outbox AS e
      ON e.tenant_id = c.tenant_id
      AND e.sandbox_uid = c.sandbox_uid
      AND e.command_id = c.command_id
      AND e.generation = c.generation
    WHERE e.event_id IS NULL
       OR e.event_type IS DISTINCT FROM 'sandbox.command.permit-unavailable'
       OR e.payload IS DISTINCT FROM jsonb_build_object(
         'run_id', c.run_id,
         'runtime_attempt_id', c.runtime_attempt_id,
         'request_digest', c.request_digest)
  ) THEN
    RAISE EXCEPTION 'sandbox CommandJournal has inconsistent original Outbox; migration refused';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION sandbox_deny_command_journal_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'sandbox pre-Permit CommandJournal and Outbox are append-only';
END;
$$;

-- Row UPDATE/DELETE cannot be used to rewrite or erase historical command
-- facts; a statement TRUNCATE trigger is needed separately, including CASCADE.
CREATE OR REPLACE TRIGGER sandbox_journal_commands_no_update_delete
BEFORE UPDATE OR DELETE ON sandbox_journal_commands
FOR EACH ROW EXECUTE FUNCTION sandbox_deny_command_journal_mutation();

CREATE OR REPLACE TRIGGER sandbox_journal_commands_no_truncate
BEFORE TRUNCATE ON sandbox_journal_commands
FOR EACH STATEMENT EXECUTE FUNCTION sandbox_deny_command_journal_mutation();

CREATE OR REPLACE TRIGGER sandbox_journal_outbox_no_update_delete
BEFORE UPDATE OR DELETE ON sandbox_journal_outbox
FOR EACH ROW EXECUTE FUNCTION sandbox_deny_command_journal_mutation();

CREATE OR REPLACE TRIGGER sandbox_journal_outbox_no_truncate
BEFORE TRUNCATE ON sandbox_journal_outbox
FOR EACH STATEMENT EXECUTE FUNCTION sandbox_deny_command_journal_mutation();

COMMIT;
