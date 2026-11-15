BEGIN;

-- P0-2B3A records an immutable intention BEFORE any remote S3 PUT.
-- Dispositions append observations; UNKNOWN never silently becomes FAILED.
-- No delete permission, claim for delete, or S3 lifecycle action exists here.
CREATE TABLE workspace_upload_intents (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    owner_principal_id text NOT NULL,
    intent_id text NOT NULL,
    source_run_intent_id uuid NOT NULL,
    session_id text NOT NULL,
    das_digest text NOT NULL CHECK (das_digest ~ '^sha256:[0-9a-f]{64}$'),
    asset_path text NOT NULL CHECK (length(asset_path) BETWEEN 1 AND 512),
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 0 AND 8388608),
    lease_seconds bigint NOT NULL CHECK (lease_seconds BETWEEN 1 AND 86400),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT workspace_upload_intents_pkey
        PRIMARY KEY (tenant_id,workspace_id,intent_id),
    CONSTRAINT workspace_upload_intents_owner_identity UNIQUE
        (tenant_id,workspace_id,intent_id,owner_principal_id),
    CONSTRAINT workspace_upload_intent_owner_fkey FOREIGN KEY
        (tenant_id,workspace_id,owner_principal_id)
        REFERENCES research_workspaces (tenant_id,workspace_id,owner_principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT workspace_upload_intent_source_fkey FOREIGN KEY
        (source_run_intent_id,tenant_id,owner_principal_id,workspace_id,session_id,das_digest)
        REFERENCES run_capability_locks
        (run_intent_id,tenant_id,principal_id,workspace_id,session_id,artifact_digest)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE workspace_upload_observations (
    observation_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    owner_principal_id text NOT NULL,
    intent_id text NOT NULL,
    disposition text NOT NULL CHECK (disposition IN ('UNKNOWN','VERIFIED')),
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT workspace_upload_observation_intent_fkey FOREIGN KEY
        (tenant_id,workspace_id,intent_id,owner_principal_id)
        REFERENCES workspace_upload_intents
            (tenant_id,workspace_id,intent_id,owner_principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE INDEX workspace_upload_intents_scope_expires
    ON workspace_upload_intents(tenant_id,workspace_id,owner_principal_id,expires_at);

CREATE INDEX workspace_upload_observations_scope_intent
    ON workspace_upload_observations(tenant_id,workspace_id,intent_id,observation_id);

ALTER TABLE workspace_upload_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_upload_intents FORCE ROW LEVEL SECURITY;
ALTER TABLE workspace_upload_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_upload_observations FORCE ROW LEVEL SECURITY;

CREATE POLICY workspace_upload_intent_scope ON workspace_upload_intents
    FOR ALL
    USING (tenant_id=current_setting('app.tenant_id',true)
       AND owner_principal_id=current_setting('app.principal_id',true))
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)
       AND owner_principal_id=current_setting('app.principal_id',true));

CREATE POLICY workspace_upload_observation_scope ON workspace_upload_observations
    FOR ALL
    USING (tenant_id=current_setting('app.tenant_id',true)
       AND owner_principal_id=current_setting('app.principal_id',true))
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)
       AND owner_principal_id=current_setting('app.principal_id',true));

CREATE FUNCTION reject_workspace_upload_evidence_mutation()
RETURNS trigger LANGUAGE plpgsql AS $workspace_upload_evidence$
BEGIN
    RAISE EXCEPTION 'Workspace upload evidence is immutable';
END;
$workspace_upload_evidence$;

CREATE TRIGGER workspace_upload_intents_no_update_delete
BEFORE UPDATE OR DELETE ON workspace_upload_intents
FOR EACH ROW EXECUTE FUNCTION reject_workspace_upload_evidence_mutation();

CREATE TRIGGER workspace_upload_intents_no_truncate
BEFORE TRUNCATE ON workspace_upload_intents
FOR EACH STATEMENT EXECUTE FUNCTION reject_workspace_upload_evidence_mutation();

CREATE TRIGGER workspace_upload_observations_no_update_delete
BEFORE UPDATE OR DELETE ON workspace_upload_observations
FOR EACH ROW EXECUTE FUNCTION reject_workspace_upload_evidence_mutation();

CREATE TRIGGER workspace_upload_observations_no_truncate
BEFORE TRUNCATE ON workspace_upload_observations
FOR EACH STATEMENT EXECUTE FUNCTION reject_workspace_upload_evidence_mutation();

REVOKE ALL ON FUNCTION reject_workspace_upload_evidence_mutation() FROM PUBLIC;

COMMIT;
