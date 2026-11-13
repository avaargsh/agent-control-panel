BEGIN;

-- Existing pre-v4 rows stay explicitly unverified (all five NULL). They can
-- be read and reconciled, but cannot be newly dispatched without a snapshot.
ALTER TABLE run_intents
    ADD COLUMN principal_snapshot_version text,
    ADD COLUMN principal_subject_id text,
    ADD COLUMN principal_actor_id text,
    ADD COLUMN principal_policy_revision text,
    ADD COLUMN principal_config_digest text,
    ADD CONSTRAINT run_intents_principal_snapshot_consistency CHECK (
        (
            principal_snapshot_version IS NULL AND
            principal_subject_id IS NULL AND
            principal_actor_id IS NULL AND
            principal_policy_revision IS NULL AND
            principal_config_digest IS NULL
        ) OR (
            principal_snapshot_version = 'acp-principal/v1' AND
            length(project_id) BETWEEN 1 AND 256 AND
            project_id = btrim(project_id) AND
            project_id !~ '[[:cntrl:]]' AND
            principal_subject_id IS NOT NULL AND
            length(principal_subject_id) BETWEEN 1 AND 256 AND
            principal_subject_id = btrim(principal_subject_id) AND
            principal_subject_id !~ '[[:cntrl:]]' AND
            principal_actor_id IS NOT NULL AND
            length(principal_actor_id) BETWEEN 1 AND 256 AND
            principal_actor_id = btrim(principal_actor_id) AND
            principal_actor_id !~ '[[:cntrl:]]' AND
            principal_policy_revision IS NOT NULL AND
            length(principal_policy_revision) BETWEEN 1 AND 256 AND
            principal_policy_revision = btrim(principal_policy_revision) AND
            principal_policy_revision !~ '[[:cntrl:]]' AND
            principal_config_digest ~ '^sha256:[0-9a-f]{64}$'
        )
    );

CREATE FUNCTION reject_run_intent_principal_snapshot_mutation()
RETURNS trigger LANGUAGE plpgsql AS $principal_snapshot$
BEGIN
    IF NEW.principal_snapshot_version IS DISTINCT FROM OLD.principal_snapshot_version
        OR NEW.principal_subject_id IS DISTINCT FROM OLD.principal_subject_id
        OR NEW.principal_actor_id IS DISTINCT FROM OLD.principal_actor_id
        OR NEW.principal_policy_revision IS DISTINCT FROM OLD.principal_policy_revision
        OR NEW.principal_config_digest IS DISTINCT FROM OLD.principal_config_digest THEN
        RAISE EXCEPTION 'RunIntent principal snapshot is immutable';
    END IF;
    RETURN NEW;
END
$principal_snapshot$;

CREATE TRIGGER run_intent_principal_snapshot_immutable
BEFORE UPDATE OF
    principal_snapshot_version,
    principal_subject_id,
    principal_actor_id,
    principal_policy_revision,
    principal_config_digest
ON run_intents
FOR EACH ROW EXECUTE FUNCTION reject_run_intent_principal_snapshot_mutation();

CREATE FUNCTION require_run_intent_principal_snapshot_for_dispatch()
RETURNS trigger LANGUAGE plpgsql AS $dispatch_gate$
BEGIN
    IF NEW.status = 'DISPATCHING' AND NEW.principal_snapshot_version IS NULL THEN
        RAISE EXCEPTION 'RunIntent cannot dispatch without an immutable principal snapshot';
    END IF;
    RETURN NEW;
END
$dispatch_gate$;

CREATE TRIGGER run_intent_dispatch_requires_principal_snapshot
BEFORE INSERT OR UPDATE OF status ON run_intents
FOR EACH ROW EXECUTE FUNCTION require_run_intent_principal_snapshot_for_dispatch();

REVOKE ALL ON FUNCTION reject_run_intent_principal_snapshot_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION require_run_intent_principal_snapshot_for_dispatch() FROM PUBLIC;

COMMIT;
