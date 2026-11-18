BEGIN;

-- ACP-owned admission authority. Only trusted catalog provisioning may
-- write these rows; an empty catalog grants nothing. No users or roles are
-- seeded by this migration.
CREATE TABLE admission_tenants (
    tenant_id text PRIMARY KEY CHECK (length(tenant_id) BETWEEN 1 AND 255),
    enabled boolean NOT NULL
);

CREATE TABLE admission_projects (
    tenant_id text NOT NULL REFERENCES admission_tenants(tenant_id),
    project_id text NOT NULL CHECK (length(project_id) BETWEEN 1 AND 255),
    enabled boolean NOT NULL,
    policy_revision text NOT NULL CHECK (length(policy_revision) BETWEEN 1 AND 255),
    PRIMARY KEY (tenant_id, project_id)
);

CREATE TABLE admission_principals (
    tenant_id text NOT NULL REFERENCES admission_tenants(tenant_id),
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    external_subject text NOT NULL CHECK (length(external_subject) BETWEEN 1 AND 255),
    principal_id text NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 255),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 255),
    enabled boolean NOT NULL,
    PRIMARY KEY (tenant_id, issuer, external_subject),
    UNIQUE (tenant_id, principal_id),
    UNIQUE (tenant_id, subject_id)
);

CREATE TABLE admission_memberships (
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    principal_id text NOT NULL,
    client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 255),
    role text NOT NULL CHECK (role IN ('RUNNER','VIEWER')),
    enabled boolean NOT NULL,
    PRIMARY KEY (tenant_id, project_id, principal_id, client_id),
    FOREIGN KEY (tenant_id, project_id) REFERENCES admission_projects(tenant_id, project_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES admission_principals(tenant_id, principal_id)
);

CREATE TABLE admission_releases (
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    agent_id text NOT NULL CHECK (length(agent_id) BETWEEN 1 AND 255),
    release_id text NOT NULL CHECK (length(release_id) BETWEEN 1 AND 255),
    config_digest text NOT NULL CHECK (config_digest ~ '^sha256:[0-9a-f]{64}$'),
    enabled boolean NOT NULL,
    PRIMARY KEY (tenant_id, project_id, agent_id, release_id),
    FOREIGN KEY (tenant_id, project_id) REFERENCES admission_projects(tenant_id, project_id)
);

CREATE TABLE admission_sessions (
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    session_id text NOT NULL CHECK (length(session_id) BETWEEN 1 AND 255),
    agent_id text NOT NULL,
    release_id text NOT NULL,
    owner_principal_id text NOT NULL,
    enabled boolean NOT NULL,
    PRIMARY KEY (tenant_id, project_id, session_id),
    FOREIGN KEY (tenant_id, project_id, agent_id, release_id)
        REFERENCES admission_releases(tenant_id, project_id, agent_id, release_id),
    FOREIGN KEY (tenant_id, owner_principal_id) REFERENCES admission_principals(tenant_id, principal_id)
);

COMMIT;
