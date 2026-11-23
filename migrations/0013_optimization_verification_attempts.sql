BEGIN;

-- ACP-owned, review-only attempt journal. This table NEVER grants execution,
-- creates PRs, authorizes protected effects, releases a GPU or posts cost.
-- Only an independently authenticated host may issue and consume attempts.
CREATE TABLE optimization_verification_attempts (
    verification_nonce text PRIMARY KEY CHECK (verification_nonce ~ '^[0-9a-f]{64}$'),
    tenant_id text NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 255),
    project_id text NOT NULL CHECK (length(project_id) BETWEEN 1 AND 255),
    experiment_id text NOT NULL CHECK (length(experiment_id) BETWEEN 1 AND 255),
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    signed_receipt_digest text CHECK (signed_receipt_digest IS NULL OR signed_receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    baseline_evidence_digest text CHECK (baseline_evidence_digest IS NULL OR baseline_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
    candidate_evidence_digest text CHECK (candidate_evidence_digest IS NULL OR candidate_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
    verifier_run_id text CHECK (verifier_run_id IS NULL OR verifier_run_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CONSTRAINT optimization_attempt_lifetime CHECK (expires_at > issued_at),
    CONSTRAINT optimization_attempt_consumption_consistency CHECK (
        (consumed_at IS NULL AND signed_receipt_digest IS NULL
            AND baseline_evidence_digest IS NULL AND candidate_evidence_digest IS NULL
            AND verifier_run_id IS NULL)
        OR
        (consumed_at IS NOT NULL AND consumed_at <= expires_at
            AND signed_receipt_digest IS NOT NULL
            AND baseline_evidence_digest IS NOT NULL
            AND candidate_evidence_digest IS NOT NULL
            AND verifier_run_id IS NOT NULL)
    )
);
-- A verifier Run may be consumed once within the exact tenant/project,
-- independently of whether a second attempt has a different nonce.
CREATE UNIQUE INDEX optimization_attempt_verifier_run_unique
    ON optimization_verification_attempts (tenant_id, project_id, verifier_run_id)
    WHERE consumed_at IS NOT NULL;

ALTER TABLE optimization_verification_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE optimization_verification_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY optimization_attempt_scope ON optimization_verification_attempts FOR ALL
    USING (tenant_id=current_setting('app.tenant_id',true)
       AND project_id=current_setting('app.project_id',true))
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)
       AND project_id=current_setting('app.project_id',true));

-- Append-only intent, one irreversible transition to consumed. No cleanup or
-- TTL-expiry deletion is permitted by the application role.
CREATE FUNCTION reject_optimization_attempt_mutation()
RETURNS trigger LANGUAGE plpgsql AS $attempt$
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'optimization attempt is immutable';
    END IF;
    IF OLD.consumed_at IS NOT NULL
        OR NEW.verification_nonce IS DISTINCT FROM OLD.verification_nonce
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.project_id IS DISTINCT FROM OLD.project_id
        OR NEW.experiment_id IS DISTINCT FROM OLD.experiment_id
        OR NEW.policy_digest IS DISTINCT FROM OLD.policy_digest
        OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
        OR NEW.consumed_at IS NULL
        OR NEW.signed_receipt_digest IS NULL
        OR NEW.baseline_evidence_digest IS NULL
        OR NEW.candidate_evidence_digest IS NULL
        OR NEW.verifier_run_id IS NULL THEN
        RAISE EXCEPTION 'optimization attempt only allows irreversible receipt consumption';
    END IF;
    RETURN NEW;
END;
$attempt$;

CREATE TRIGGER optimization_attempt_no_reset_or_delete
    BEFORE UPDATE OR DELETE ON optimization_verification_attempts
    FOR EACH ROW EXECUTE FUNCTION reject_optimization_attempt_mutation();
CREATE TRIGGER optimization_attempt_no_truncate
    BEFORE TRUNCATE ON optimization_verification_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION reject_optimization_attempt_mutation();
ALTER TABLE optimization_verification_attempts ENABLE ALWAYS TRIGGER optimization_attempt_no_reset_or_delete;
ALTER TABLE optimization_verification_attempts ENABLE ALWAYS TRIGGER optimization_attempt_no_truncate;
REVOKE ALL ON FUNCTION reject_optimization_attempt_mutation() FROM PUBLIC;

COMMIT;
