BEGIN;
-- ACP DLQ disposition ledger. This records immutable publication intent and
-- evidence digest, but it does not grant approval or make broker PubAck and
-- PostgreSQL commit atomic. Service roles and broker ACLs are separate gates.
CREATE TABLE dlq_dispositions (
    tenant_id text NOT NULL CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    consumer_name text NOT NULL CHECK (consumer_name <> ''),
    source_stream text NOT NULL CHECK (source_stream <> ''),
    source_consumer text NOT NULL CHECK (source_consumer <> ''),
    source_sequence bigint NOT NULL CHECK (source_sequence > 0),
    delivery_sha256 text NOT NULL CHECK (delivery_sha256 ~ '^[a-f0-9]{64}$'),
    reason text NOT NULL CHECK (reason IN ('EVENT_ID_CONFLICT','INBOX_QUARANTINED')),
    dlq_stream text NOT NULL CHECK (dlq_stream <> ''),
    dlq_subject text NOT NULL CHECK (dlq_subject <> ''),
    evidence bytea NOT NULL CHECK (octet_length(evidence) > 0),
    publish_started boolean NOT NULL DEFAULT false,
    published boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    published_at timestamptz,
    PRIMARY KEY (source_stream, source_consumer, source_sequence),
    CONSTRAINT dlq_published_consistency CHECK (
        (published AND published_at IS NOT NULL) OR
        (NOT published AND published_at IS NULL)
    ),
    CONSTRAINT dlq_requires_attempt CHECK (NOT published OR publish_started)
);

-- Note: plpgsql's TG_OP and trigger timing guard both existing and future
-- disposition records against changes to immutable identity and evidence.
CREATE FUNCTION reject_dlq_disposition_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'DLQ disposition evidence is append-only';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.consumer_name IS DISTINCT FROM OLD.consumer_name
        OR NEW.source_stream IS DISTINCT FROM OLD.source_stream
        OR NEW.source_consumer IS DISTINCT FROM OLD.source_consumer
        OR NEW.source_sequence IS DISTINCT FROM OLD.source_sequence
        OR NEW.delivery_sha256 IS DISTINCT FROM OLD.delivery_sha256
        OR NEW.reason IS DISTINCT FROM OLD.reason
        OR NEW.dlq_stream IS DISTINCT FROM OLD.dlq_stream
        OR NEW.dlq_subject IS DISTINCT FROM OLD.dlq_subject
        OR NEW.evidence IS DISTINCT FROM OLD.evidence
        OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'immutable DLQ disposition identity or evidence changed';
    END IF;
    IF (OLD.publish_started AND NOT NEW.publish_started)
        OR (OLD.published AND (NOT NEW.published OR NEW.published_at IS DISTINCT FROM OLD.published_at))
        OR (NEW.published AND NOT OLD.publish_started) THEN
        RAISE EXCEPTION 'DLQ disposition publication state rollback';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER dlq_disposition_no_unsafe_update_delete
BEFORE UPDATE OR DELETE ON dlq_dispositions
FOR EACH ROW EXECUTE FUNCTION reject_dlq_disposition_mutation();
CREATE TRIGGER dlq_disposition_no_truncate
BEFORE TRUNCATE ON dlq_dispositions
FOR EACH STATEMENT EXECUTE FUNCTION reject_dlq_disposition_mutation();

-- A migration owner does not authorize production writers. Application grant
-- policy must be issued independently, reviewed and validated with real roles.
REVOKE ALL ON TABLE dlq_dispositions FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_dlq_disposition_mutation() FROM PUBLIC;
COMMIT;
