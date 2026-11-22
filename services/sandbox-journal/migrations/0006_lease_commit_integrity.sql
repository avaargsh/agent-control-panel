-- Independent Sandbox Service database only. Add after migration 0005.
-- Fail closed at COMMIT: a lease intent and its exact original Outbox facts
-- must be an indivisible source-owned history, not merely consistent at read.
-- This provides NO Guard Permit, real SandboxLease, AgentD command or release.
BEGIN;

LOCK TABLE public.sandbox_lease_intents, public.sandbox_lease_intent_events
  IN SHARE ROW EXCLUSIVE MODE;

-- Do not install a new source-of-truth barrier over already corrupted rows.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.sandbox_lease_intents AS i
    CROSS JOIN LATERAL (
      SELECT
        count(*) AS total,
        count(*) FILTER (
          WHERE e.generation BETWEEN 1 AND i.generation
            AND e.event_type = CASE e.generation
              WHEN 1 THEN 'sandbox.lease-intent.waiting-permit'
              WHEN 2 THEN 'sandbox.lease-intent.cancelled-before-provision'
              ELSE ''
            END
            AND e.payload = jsonb_build_object(
              'run_id', i.run_id,
              'runtime_attempt_id', i.runtime_attempt_id,
              'request_digest', i.request_digest)
        ) AS valid
      FROM public.sandbox_lease_intent_events AS e
      WHERE e.tenant_id = i.tenant_id
        AND e.lease_intent_id = i.lease_intent_id
    ) AS history
    WHERE history.total <> i.generation OR history.valid <> i.generation
  ) THEN
    RAISE EXCEPTION 'sandbox lease state/outbox history is incomplete or forged; migration refused';
  END IF;
END;
$$;

-- Deferrable constraint triggers evaluate the COMPLETE transaction at
-- commit, after the Go writer has inserted the state+outbox or CAS+outbox.
-- A plain CHECK/BEFORE INSERT trigger would reject valid atomic two-step
-- writes before their matching event is inserted.
CREATE OR REPLACE FUNCTION public.sandbox_require_complete_lease_history()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  bound_generation bigint;
  bound_run text;
  bound_attempt text;
  bound_digest text;
  event_count bigint;
  matching_count bigint;
BEGIN
  -- NEW always exists: triggers fire only on state INSERT/UPDATE and event INSERT.
  SELECT i.generation, i.run_id, i.runtime_attempt_id, i.request_digest
    INTO bound_generation, bound_run, bound_attempt, bound_digest
  FROM public.sandbox_lease_intents AS i
  WHERE i.tenant_id = NEW.tenant_id AND i.lease_intent_id = NEW.lease_intent_id
  FOR UPDATE;

  IF NOT FOUND OR bound_generation NOT IN (1, 2) THEN
    RAISE EXCEPTION 'sandbox lease commit missing or invalid state'
      USING ERRCODE = '23514';
  END IF;

  SELECT count(*),
    count(*) FILTER (
      WHERE e.generation BETWEEN 1 AND bound_generation
        AND e.event_type = CASE e.generation
          WHEN 1 THEN 'sandbox.lease-intent.waiting-permit'
          WHEN 2 THEN 'sandbox.lease-intent.cancelled-before-provision'
          ELSE ''
        END
        AND e.payload = jsonb_build_object(
          'run_id', bound_run,
          'runtime_attempt_id', bound_attempt,
          'request_digest', bound_digest)
    )
  INTO event_count, matching_count
  FROM public.sandbox_lease_intent_events AS e
  WHERE e.tenant_id = NEW.tenant_id
    AND e.lease_intent_id = NEW.lease_intent_id;

  IF event_count <> bound_generation OR matching_count <> bound_generation THEN
    RAISE EXCEPTION 'sandbox lease commit requires exact state and original Outbox events'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$;

-- Dropping and recreating inside one writer-blocking transaction makes this
-- migration idempotent without exposing a momentary unguarded window.
DROP TRIGGER IF EXISTS sandbox_lease_complete_state_commit
  ON public.sandbox_lease_intents;
CREATE CONSTRAINT TRIGGER sandbox_lease_complete_state_commit
AFTER INSERT OR UPDATE ON public.sandbox_lease_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.sandbox_require_complete_lease_history();

DROP TRIGGER IF EXISTS sandbox_lease_complete_event_commit
  ON public.sandbox_lease_intent_events;
CREATE CONSTRAINT TRIGGER sandbox_lease_complete_event_commit
AFTER INSERT ON public.sandbox_lease_intent_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.sandbox_require_complete_lease_history();

-- No untrusted direct CALL is needed; PostgreSQL invokes this as an owner-
-- installed trigger. Runtime principals cannot alter trigger definitions.
REVOKE ALL ON FUNCTION public.sandbox_require_complete_lease_history()
  FROM PUBLIC;

COMMIT;
