-- Independent Sandbox Service PostgreSQL database ONLY; additive after 0010.
-- Pre-Permit PERMIT_UNAVAILABLE facts are NOT dispatched commands.
-- Enforce atomic Command + original Outbox integrity at COMMIT, even when
-- a least-privileged Command writer bypasses the Go repository wrapper.
-- This is not a Guard Permit, AgentD effect, UNKNOWN or release receipt.
BEGIN;

-- Block new source writes until the entire preexisting append-only history
-- is checked and the deferred triggers are installed in one transaction.
LOCK TABLE public.sandbox_journal_commands, public.sandbox_journal_outbox
  IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.sandbox_journal_commands AS c
    LEFT JOIN public.sandbox_journal_outbox AS e
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
    RAISE EXCEPTION 'sandbox Command/Outbox history incomplete or forged; migration refused'
      USING ERRCODE = '23514';
  END IF;
END;
$$;

-- Both INSERT paths schedule this exact same source-owned check for commit.
-- Ordinary BEFORE INSERT constraints would reject the valid two-step
-- atomic repository transaction before its Outbox INSERT can occur.
CREATE OR REPLACE FUNCTION public.sandbox_require_complete_command_history()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_run text;
  v_attempt text;
  v_digest text;
  v_generation bigint;
  v_event_count bigint;
  v_exact_count bigint;
BEGIN
  SELECT c.run_id, c.runtime_attempt_id, c.request_digest, c.generation
    INTO v_run, v_attempt, v_digest, v_generation
  FROM public.sandbox_journal_commands AS c
  WHERE c.tenant_id = NEW.tenant_id
    AND c.sandbox_uid = NEW.sandbox_uid
    AND c.command_id = NEW.command_id;

  IF NOT FOUND OR v_generation <> 1 THEN
    RAISE EXCEPTION 'sandbox Command commit missing original source record'
      USING ERRCODE = '23514';
  END IF;

  SELECT count(*),
    count(*) FILTER (
      WHERE e.generation = v_generation
        AND e.event_type = 'sandbox.command.permit-unavailable'
        AND e.payload = jsonb_build_object(
          'run_id', v_run,
          'runtime_attempt_id', v_attempt,
          'request_digest', v_digest)
    )
  INTO v_event_count, v_exact_count
  FROM public.sandbox_journal_outbox AS e
  WHERE e.tenant_id = NEW.tenant_id
    AND e.sandbox_uid = NEW.sandbox_uid
    AND e.command_id = NEW.command_id;

  IF v_event_count <> 1 OR v_exact_count <> 1 THEN
    RAISE EXCEPTION 'sandbox Command commit requires exactly one bound original Outbox'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS sandbox_command_complete_source_commit
  ON public.sandbox_journal_commands;
CREATE CONSTRAINT TRIGGER sandbox_command_complete_source_commit
AFTER INSERT ON public.sandbox_journal_commands
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.sandbox_require_complete_command_history();

DROP TRIGGER IF EXISTS sandbox_command_complete_outbox_commit
  ON public.sandbox_journal_outbox;
CREATE CONSTRAINT TRIGGER sandbox_command_complete_outbox_commit
AFTER INSERT ON public.sandbox_journal_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.sandbox_require_complete_command_history();

-- Only the owner-installed triggers invoke this trusted check. This does
-- not confer a direct mutation or execution capability on a service role.
REVOKE ALL ON FUNCTION public.sandbox_require_complete_command_history()
  FROM PUBLIC, acp_sandbox_command_writer, acp_sandbox_command_reader,
       acp_sandbox_lease_writer, acp_sandbox_lease_reader;

COMMIT;
