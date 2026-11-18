BEGIN;

-- Legacy digest-only intents retain NULL. Input is set only at creation.
ALTER TABLE run_intents
    ADD COLUMN execution_input bytea,
    ADD CONSTRAINT run_intents_execution_input_size
        CHECK (execution_input IS NULL OR octet_length(execution_input) BETWEEN 2 AND 262144);

CREATE FUNCTION reject_run_intent_execution_input_mutation()
RETURNS trigger LANGUAGE plpgsql AS $input$
BEGIN
    IF NEW.execution_input IS DISTINCT FROM OLD.execution_input
        OR (OLD.execution_input IS NOT NULL AND (
            NEW.id IS DISTINCT FROM OLD.id
            OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
            OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
            OR NEW.project_id IS DISTINCT FROM OLD.project_id
            OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
            OR NEW.release_id IS DISTINCT FROM OLD.release_id
            OR NEW.session_id IS DISTINCT FROM OLD.session_id
            OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
            OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
        )) THEN
        RAISE EXCEPTION 'RunIntent execution input binding is immutable';
    END IF;
    RETURN NEW;
END;
$input$;

CREATE TRIGGER run_intent_execution_input_immutable
BEFORE UPDATE ON run_intents
FOR EACH ROW EXECUTE FUNCTION reject_run_intent_execution_input_mutation();

REVOKE ALL ON FUNCTION reject_run_intent_execution_input_mutation() FROM PUBLIC;

COMMIT;
