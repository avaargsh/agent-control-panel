BEGIN;
-- Persist a conflicting redelivery before the broker is permitted to ACK.
-- The original Inbox event may already be APPLIED and must remain untouched.
CREATE TABLE inbox_event_conflicts (
    consumer_name text NOT NULL CHECK (consumer_name <> ''),
    event_id uuid NOT NULL,
    conflict_sha256 text NOT NULL CHECK (conflict_sha256 ~ '^[0-9a-f]{64}$'),
    producer text NOT NULL CHECK (producer <> ''),
    event_type text NOT NULL CHECK (event_type <> ''),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    tenant_id text NOT NULL CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    aggregate_type text NOT NULL CHECK (aggregate_type <> ''),
    aggregate_id text NOT NULL CHECK (aggregate_id <> ''),
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (consumer_name,event_id,conflict_sha256),
    CONSTRAINT inbox_event_conflicts_original_fkey
        FOREIGN KEY (consumer_name,event_id)
        REFERENCES inbox_events (consumer_name,event_id)
);
CREATE OR REPLACE FUNCTION reject_inbox_conflict_evidence_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'inbox conflict evidence is append-only';
END;
$$;
CREATE TRIGGER inbox_conflict_evidence_no_update_delete
BEFORE UPDATE OR DELETE ON inbox_event_conflicts
FOR EACH ROW EXECUTE FUNCTION reject_inbox_conflict_evidence_mutation();
CREATE TRIGGER inbox_conflict_evidence_no_truncate
BEFORE TRUNCATE ON inbox_event_conflicts
FOR EACH STATEMENT EXECUTE FUNCTION reject_inbox_conflict_evidence_mutation();
COMMIT;
