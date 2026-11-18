BEGIN;

-- Historic authentication origin is fixed at admission, not a reusable
-- OAuth token. Legacy NULL rows must not acquire an origin by UPDATE.
ALTER TABLE run_intents
    ADD COLUMN admission_issuer text,
    ADD COLUMN admission_external_subject text,
    ADD COLUMN admission_client_id text,
    ADD CONSTRAINT run_intents_admission_origin_consistency CHECK (
        (admission_issuer IS NULL AND admission_external_subject IS NULL AND admission_client_id IS NULL)
        OR (admission_issuer IS NOT NULL AND admission_external_subject IS NOT NULL AND admission_client_id IS NOT NULL
            AND length(admission_issuer) BETWEEN 1 AND 2048
            AND length(admission_external_subject) BETWEEN 1 AND 255
            AND length(admission_client_id) BETWEEN 1 AND 255
            AND execution_input IS NOT NULL
            AND principal_snapshot_version = 'acp-principal/v1'
            AND principal_subject_id IS NOT NULL AND principal_actor_id IS NOT NULL
            AND principal_subject_id = principal_actor_id)
    );

CREATE FUNCTION reject_run_intent_admission_origin_mutation()
RETURNS trigger LANGUAGE plpgsql AS $origin$
BEGIN
    IF NEW.admission_issuer IS DISTINCT FROM OLD.admission_issuer
        OR NEW.admission_external_subject IS DISTINCT FROM OLD.admission_external_subject
        OR NEW.admission_client_id IS DISTINCT FROM OLD.admission_client_id
        OR (OLD.admission_issuer IS NOT NULL AND OLD.status = 'ACCEPTED' AND (
            NEW.status IS DISTINCT FROM OLD.status
            OR NEW.runtime_run_id IS DISTINCT FROM OLD.runtime_run_id
            OR NEW.workflow_id IS DISTINCT FROM OLD.workflow_id
        )) THEN
        RAISE EXCEPTION 'RunIntent admission origin and accepted Runtime binding are immutable';
    END IF;
    RETURN NEW;
END;
$origin$;

CREATE TRIGGER run_intent_admission_origin_immutable
BEFORE UPDATE ON run_intents
FOR EACH ROW EXECUTE FUNCTION reject_run_intent_admission_origin_mutation();
ALTER TABLE run_intents ENABLE ALWAYS TRIGGER run_intent_admission_origin_immutable;
REVOKE ALL ON FUNCTION reject_run_intent_admission_origin_mutation() FROM PUBLIC;

COMMIT;
