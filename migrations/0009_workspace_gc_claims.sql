BEGIN;

-- v9 is a metadata-only GC fencing ledger. It has NO S3 DELETE authority,
-- no tombstone producer and no background cleanup worker.
CREATE TABLE workspace_gc_claims (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    owner_principal_id text NOT NULL,
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    holder_id text NOT NULL CHECK (length(holder_id) BETWEEN 1 AND 128),
    generation bigint NOT NULL CHECK (generation > 0),
    lease_seconds bigint NOT NULL CHECK (lease_seconds BETWEEN 1 AND 300),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT workspace_gc_claims_pkey PRIMARY KEY (tenant_id,workspace_id,artifact_digest),
    CONSTRAINT workspace_gc_claims_owner_key UNIQUE (tenant_id,workspace_id,artifact_digest,owner_principal_id),
    CONSTRAINT workspace_gc_claims_owner_fkey FOREIGN KEY (tenant_id,workspace_id,owner_principal_id)
        REFERENCES research_workspaces (tenant_id,workspace_id,owner_principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE workspace_gc_observations (
    observation_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    owner_principal_id text NOT NULL,
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    holder_id text NOT NULL CHECK (length(holder_id) BETWEEN 1 AND 128),
    generation bigint NOT NULL CHECK (generation >= 0),
    disposition text NOT NULL CHECK (disposition IN
        ('ACQUIRED','RECLAIMED','RENEWED','NOT_ELIGIBLE','UNKNOWN')),
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT workspace_gc_observations_owner_fkey FOREIGN KEY
        (tenant_id,workspace_id,owner_principal_id)
        REFERENCES research_workspaces (tenant_id,workspace_id,owner_principal_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE INDEX workspace_gc_observations_scope_digest
    ON workspace_gc_observations (tenant_id,workspace_id,artifact_digest,observation_id);

ALTER TABLE workspace_gc_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_gc_claims FORCE ROW LEVEL SECURITY;
ALTER TABLE workspace_gc_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_gc_observations FORCE ROW LEVEL SECURITY;

CREATE POLICY workspace_gc_claim_scope ON workspace_gc_claims FOR ALL
    USING (tenant_id=current_setting('app.tenant_id',true)
       AND owner_principal_id=current_setting('app.principal_id',true))
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)
       AND owner_principal_id=current_setting('app.principal_id',true));

CREATE POLICY workspace_gc_observation_scope ON workspace_gc_observations FOR ALL
    USING (tenant_id=current_setting('app.tenant_id',true)
       AND owner_principal_id=current_setting('app.principal_id',true))
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)
       AND owner_principal_id=current_setting('app.principal_id',true));

CREATE FUNCTION reject_workspace_gc_identity_mutation()
RETURNS trigger LANGUAGE plpgsql AS $gc_identity$
BEGIN
    RAISE EXCEPTION 'Workspace GC identity cannot be mutated or removed';
END;
$gc_identity$;

CREATE TRIGGER workspace_gc_claims_no_identity_change
BEFORE UPDATE OF tenant_id, workspace_id, owner_principal_id, artifact_digest
ON workspace_gc_claims FOR EACH ROW EXECUTE FUNCTION reject_workspace_gc_identity_mutation();

CREATE TRIGGER workspace_gc_claims_no_delete
BEFORE DELETE ON workspace_gc_claims
FOR EACH ROW EXECUTE FUNCTION reject_workspace_gc_identity_mutation();

CREATE TRIGGER workspace_gc_claims_no_truncate
BEFORE TRUNCATE ON workspace_gc_claims
FOR EACH STATEMENT EXECUTE FUNCTION reject_workspace_gc_identity_mutation();

CREATE TRIGGER workspace_gc_observations_no_update_delete
BEFORE UPDATE OR DELETE ON workspace_gc_observations
FOR EACH ROW EXECUTE FUNCTION reject_workspace_gc_identity_mutation();

CREATE TRIGGER workspace_gc_observations_no_truncate
BEFORE TRUNCATE ON workspace_gc_observations
FOR EACH STATEMENT EXECUTE FUNCTION reject_workspace_gc_identity_mutation();

REVOKE ALL ON FUNCTION reject_workspace_gc_identity_mutation() FROM PUBLIC;

COMMIT;
