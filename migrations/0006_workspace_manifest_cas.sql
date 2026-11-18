BEGIN;

-- ACP is authority for Workspace identity; this metadata-only slice never
-- claims that referenced object bytes have been persisted in S3/MinIO.
CREATE UNIQUE INDEX run_capability_locks_workspace_identity
    ON run_capability_locks (
        run_intent_id, tenant_id, principal_id, workspace_id, session_id, artifact_digest
    );

CREATE TABLE research_workspaces (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    owner_principal_id text NOT NULL,
    manifest_revision bigint NOT NULL DEFAULT 0 CHECK (manifest_revision >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, workspace_id),
    CONSTRAINT research_workspaces_owner_identity UNIQUE
        (tenant_id, workspace_id, owner_principal_id)
);

CREATE TABLE workspace_manifest_commits (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    owner_principal_id text NOT NULL,
    manifest_revision bigint NOT NULL CHECK (manifest_revision > 0),
    previous_revision bigint NOT NULL CHECK (previous_revision >= 0),
    commit_id text NOT NULL,
    source_run_intent_id uuid NOT NULL,
    session_id text NOT NULL,
    das_digest text NOT NULL CHECK (das_digest ~ '^sha256:[0-9a-f]{64}$'),
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'array'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT workspace_commit_pkey PRIMARY KEY (tenant_id, workspace_id, manifest_revision),
    CONSTRAINT workspace_commit_idempotency UNIQUE (tenant_id, workspace_id, commit_id),
    CONSTRAINT workspace_commit_linear_revision CHECK (manifest_revision = previous_revision + 1),
    CONSTRAINT workspace_commit_owner_fkey FOREIGN KEY (tenant_id, workspace_id, owner_principal_id)
        REFERENCES research_workspaces (tenant_id, workspace_id, owner_principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT workspace_commit_source_fkey FOREIGN KEY (
        source_run_intent_id, tenant_id, owner_principal_id, workspace_id, session_id, das_digest
    ) REFERENCES run_capability_locks (
        run_intent_id, tenant_id, principal_id, workspace_id, session_id, artifact_digest
    ) ON UPDATE RESTRICT ON DELETE RESTRICT
);

ALTER TABLE research_workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE research_workspaces FORCE ROW LEVEL SECURITY;
ALTER TABLE workspace_manifest_commits ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_manifest_commits FORCE ROW LEVEL SECURITY;

-- Both identities are derived by the trusted caller and bound transaction
-- locally. These session settings alone are not proof of authentication.
CREATE POLICY research_workspace_scope ON research_workspaces
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true)
       AND owner_principal_id = current_setting('app.principal_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
       AND owner_principal_id = current_setting('app.principal_id', true));

CREATE POLICY workspace_manifest_scope ON workspace_manifest_commits
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true)
       AND owner_principal_id = current_setting('app.principal_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
       AND owner_principal_id = current_setting('app.principal_id', true));

CREATE FUNCTION reject_workspace_identity_mutation()
RETURNS trigger LANGUAGE plpgsql AS $workspace_identity$
BEGIN
    RAISE EXCEPTION 'Workspace identity is immutable';
END;
$workspace_identity$;

CREATE TRIGGER research_workspace_no_identity_change
BEFORE UPDATE OF tenant_id, workspace_id, owner_principal_id ON research_workspaces
FOR EACH ROW EXECUTE FUNCTION reject_workspace_identity_mutation();

CREATE TRIGGER research_workspace_no_delete
BEFORE DELETE ON research_workspaces
FOR EACH ROW EXECUTE FUNCTION reject_workspace_identity_mutation();

CREATE FUNCTION reject_workspace_commit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $workspace_commit$
BEGIN
    RAISE EXCEPTION 'Workspace commit receipt is immutable';
END;
$workspace_commit$;

CREATE TRIGGER workspace_manifest_no_update_delete
BEFORE UPDATE OR DELETE ON workspace_manifest_commits
FOR EACH ROW EXECUTE FUNCTION reject_workspace_commit_mutation();

CREATE TRIGGER workspace_manifest_no_truncate
BEFORE TRUNCATE ON workspace_manifest_commits
FOR EACH STATEMENT EXECUTE FUNCTION reject_workspace_commit_mutation();

REVOKE ALL ON FUNCTION reject_workspace_identity_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_workspace_commit_mutation() FROM PUBLIC;

COMMIT;
