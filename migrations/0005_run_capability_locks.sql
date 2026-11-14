BEGIN;

-- v5 is additive. Existing unpinned RunIntents remain valid legacy records.
-- The unique index allows a composite FK to bind the pinned release to the
-- *same* tenant, principal, ACP AgentRelease and Session as its RunIntent.
CREATE UNIQUE INDEX run_intents_capability_parent_identity
    ON run_intents (id, tenant_id, principal_id, release_id, session_id);

CREATE TABLE run_capability_locks (
    run_intent_id uuid PRIMARY KEY,
    tenant_id text NOT NULL CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    principal_id text NOT NULL CHECK (principal_id <> '' AND principal_id = btrim(principal_id)),
    agent_release_id text NOT NULL CHECK (agent_release_id <> ''),
    workspace_id text NOT NULL CHECK (workspace_id <> ''),
    session_id text NOT NULL CHECK (session_id <> ''),
    package_id text NOT NULL CHECK (package_id <> ''),
    package_version text NOT NULL CHECK (package_version <> ''),
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    subscription_id text NOT NULL CHECK (subscription_id <> ''),
    policy_revision text NOT NULL CHECK (policy_revision <> ''),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT run_capability_lock_origin_fkey
        FOREIGN KEY (run_intent_id, tenant_id, principal_id, agent_release_id, session_id)
        REFERENCES run_intents (id, tenant_id, principal_id, release_id, session_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

ALTER TABLE run_capability_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE run_capability_locks FORCE ROW LEVEL SECURITY;

-- app.tenant_id must be set transaction-locally by a server-side trusted
-- principal adapter. A client-supplied GUC is NOT authentication.
CREATE POLICY run_capability_locks_tenant
    ON run_capability_locks
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE FUNCTION reject_run_capability_lock_mutation()
RETURNS trigger LANGUAGE plpgsql AS $capability_lock$
BEGIN
    RAISE EXCEPTION 'RunIntent capability lock is immutable';
END;
$capability_lock$;

CREATE TRIGGER run_capability_lock_no_update_delete
BEFORE UPDATE OR DELETE ON run_capability_locks
FOR EACH ROW EXECUTE FUNCTION reject_run_capability_lock_mutation();

CREATE TRIGGER run_capability_lock_no_truncate
BEFORE TRUNCATE ON run_capability_locks
FOR EACH STATEMENT EXECUTE FUNCTION reject_run_capability_lock_mutation();

REVOKE ALL ON FUNCTION reject_run_capability_lock_mutation() FROM PUBLIC;

COMMIT;
