BEGIN;

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, tenant_id, agent_id)
);

CREATE TABLE IF NOT EXISTS runs (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    release_id  TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('PENDING','RUNNING','WAITING','SUCCEEDED','FAILED','CANCELLED')),
    input       JSONB NOT NULL DEFAULT '{}'::jsonb,
    version     BIGINT NOT NULL CHECK (version > 0),
    failure     TEXT,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    UNIQUE (id, tenant_id),
    FOREIGN KEY (session_id, tenant_id, agent_id) REFERENCES sessions (id, tenant_id, agent_id)
);
CREATE INDEX IF NOT EXISTS runs_tenant_created_idx ON runs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS runs_session_idx ON runs (session_id, created_at DESC);

CREATE TABLE IF NOT EXISTS idempotency_records (
    tenant_id       TEXT NOT NULL,
    operation       TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash    CHAR(64) NOT NULL,
    resource_id     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, operation, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idempotency_resource_idx ON idempotency_records (resource_id);

CREATE TABLE IF NOT EXISTS outbox_events (
    id                TEXT PRIMARY KEY,
    aggregate_type    TEXT NOT NULL,
    aggregate_id      TEXT NOT NULL,
    aggregate_version BIGINT NOT NULL,
    event_type        TEXT NOT NULL,
    payload           JSONB NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    published_at      TIMESTAMPTZ,
    attempts          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_until       TIMESTAMPTZ,
    lease_token       TEXT,
    last_error        TEXT,
    UNIQUE (aggregate_type, aggregate_id, aggregate_version)
);
CREATE INDEX IF NOT EXISTS outbox_unpublished_idx ON outbox_events (next_attempt_at, created_at) WHERE published_at IS NULL;

COMMIT;
