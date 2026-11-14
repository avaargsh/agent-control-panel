BEGIN;

-- v7 never deletes S3 objects. Stages are immutable evidence of a verified
-- object at one instant, not proof that the backend retains the bytes forever.
-- Historical Workspace manifests (v6) remain the retention authority too.
CREATE TABLE workspace_blob_stages (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    owner_principal_id text NOT NULL,
    stage_id text NOT NULL,
    source_run_intent_id uuid NOT NULL,
    session_id text NOT NULL,
    das_digest text NOT NULL CHECK (das_digest ~ '^sha256:[0-9a-f]{64}$'),
    asset_path text NOT NULL CHECK (length(asset_path) BETWEEN 1 AND 512),
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    lease_seconds bigint NOT NULL CHECK (lease_seconds BETWEEN 1 AND 86400),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT workspace_blob_stages_pkey
        PRIMARY KEY (tenant_id, workspace_id, stage_id),
    CONSTRAINT workspace_blob_stage_owner_fkey
        FOREIGN KEY (tenant_id, workspace_id, owner_principal_id)
        REFERENCES research_workspaces (tenant_id, workspace_id, owner_principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT workspace_blob_stage_source_fkey
        FOREIGN KEY (
            source_run_intent_id, tenant_id, owner_principal_id,
            workspace_id, session_id, das_digest
        ) REFERENCES run_capability_locks (
            run_intent_id, tenant_id, principal_id, workspace_id,
            session_id, artifact_digest
        ) ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE INDEX workspace_blob_stages_scope_digest
    ON workspace_blob_stages
    (tenant_id, workspace_id, owner_principal_id, artifact_digest, expires_at);

CREATE TABLE workspace_blob_commit_refs (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    owner_principal_id text NOT NULL,
    manifest_revision bigint NOT NULL,
    asset_path text NOT NULL CHECK (length(asset_path) BETWEEN 1 AND 512),
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    CONSTRAINT workspace_blob_commit_refs_pkey
        PRIMARY KEY (tenant_id, workspace_id, manifest_revision, asset_path),
    CONSTRAINT workspace_blob_ref_manifest_fkey
        FOREIGN KEY (tenant_id, workspace_id, manifest_revision)
        REFERENCES workspace_manifest_commits
            (tenant_id, workspace_id, manifest_revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE INDEX workspace_blob_commit_refs_scope_digest
    ON workspace_blob_commit_refs
    (tenant_id, workspace_id, artifact_digest);

ALTER TABLE workspace_blob_stages ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_blob_stages FORCE ROW LEVEL SECURITY;
ALTER TABLE workspace_blob_commit_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_blob_commit_refs FORCE ROW LEVEL SECURITY;

CREATE POLICY workspace_blob_stage_scope
    ON workspace_blob_stages FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true)
       AND owner_principal_id = current_setting('app.principal_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
       AND owner_principal_id = current_setting('app.principal_id', true));

CREATE POLICY workspace_blob_ref_scope
    ON workspace_blob_commit_refs FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true)
       AND owner_principal_id = current_setting('app.principal_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
       AND owner_principal_id = current_setting('app.principal_id', true));

CREATE FUNCTION reject_workspace_blob_evidence_mutation()
RETURNS trigger LANGUAGE plpgsql AS $blob_evidence$
BEGIN
    RAISE EXCEPTION 'Workspace blob evidence is immutable';
END;
$blob_evidence$;

CREATE TRIGGER workspace_blob_stages_no_update_delete
BEFORE UPDATE OR DELETE ON workspace_blob_stages
FOR EACH ROW EXECUTE FUNCTION reject_workspace_blob_evidence_mutation();

CREATE TRIGGER workspace_blob_stages_no_truncate
BEFORE TRUNCATE ON workspace_blob_stages
FOR EACH STATEMENT EXECUTE FUNCTION reject_workspace_blob_evidence_mutation();

CREATE TRIGGER workspace_blob_refs_no_update_delete
BEFORE UPDATE OR DELETE ON workspace_blob_commit_refs
FOR EACH ROW EXECUTE FUNCTION reject_workspace_blob_evidence_mutation();

CREATE TRIGGER workspace_blob_refs_no_truncate
BEFORE TRUNCATE ON workspace_blob_commit_refs
FOR EACH STATEMENT EXECUTE FUNCTION reject_workspace_blob_evidence_mutation();

REVOKE ALL ON FUNCTION reject_workspace_blob_evidence_mutation() FROM PUBLIC;

COMMIT;
