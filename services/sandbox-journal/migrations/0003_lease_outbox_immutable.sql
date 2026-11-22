-- Additive candidate migration for the independent Sandbox Service database.
-- Run AFTER 0002, never in ACP's RunIntent database. This is an owner-side
-- append-only safety barrier, not a Guard Permit or a signed evidence ledger.
BEGIN;

-- Refuse to seal already inconsistent events. A migration must not make
-- corrupted historical rows look authoritative by installing triggers.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM sandbox_lease_intents AS i
    LEFT JOIN sandbox_lease_intent_events AS created
      ON created.tenant_id = i.tenant_id
      AND created.lease_intent_id = i.lease_intent_id
      AND created.generation = 1
    LEFT JOIN sandbox_lease_intent_events AS cancelled
      ON cancelled.tenant_id = i.tenant_id
      AND cancelled.lease_intent_id = i.lease_intent_id
      AND cancelled.generation = 2
    WHERE created.event_id IS NULL
      OR created.event_type IS DISTINCT FROM 'sandbox.lease-intent.waiting-permit'
      OR created.payload IS DISTINCT FROM jsonb_build_object(
        'run_id',i.run_id,
        'runtime_attempt_id',i.runtime_attempt_id,
        'request_digest',i.request_digest)
      OR (i.generation = 2 AND (
        cancelled.event_id IS NULL
        OR cancelled.event_type IS DISTINCT FROM 'sandbox.lease-intent.cancelled-before-provision'
        OR cancelled.payload IS DISTINCT FROM jsonb_build_object(
          'run_id',i.run_id,
          'runtime_attempt_id',i.runtime_attempt_id,
          'request_digest',i.request_digest)))
      OR (i.generation = 1 AND cancelled.event_id IS NOT NULL)
  ) THEN
    RAISE EXCEPTION 'sandbox lease Outbox has inconsistent history; migration refused';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION sandbox_deny_lease_outbox_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'sandbox lease-intent Outbox is append-only';
END;
$$;

-- Protect UPDATE, DELETE and TRUNCATE independently; TRUNCATE does not fire
-- row triggers. Even no-op UPDATEs of existing rows are disallowed.
CREATE OR REPLACE TRIGGER sandbox_lease_outbox_no_update_delete
BEFORE UPDATE OR DELETE ON sandbox_lease_intent_events
FOR EACH ROW EXECUTE FUNCTION sandbox_deny_lease_outbox_mutation();

CREATE OR REPLACE TRIGGER sandbox_lease_outbox_no_truncate
BEFORE TRUNCATE ON sandbox_lease_intent_events
FOR EACH STATEMENT EXECUTE FUNCTION sandbox_deny_lease_outbox_mutation();

COMMIT;
