BEGIN;
CREATE TABLE run_intents (
 id uuid PRIMARY KEY,
 tenant_id text NOT NULL CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
 principal_id text NOT NULL CHECK (principal_id <> '' AND principal_id = btrim(principal_id)),
 operation text NOT NULL DEFAULT 'run_intent.create' CHECK (operation = 'run_intent.create'),
 project_id text NOT NULL CHECK (project_id <> '' AND project_id = btrim(project_id)),
 agent_id text NOT NULL CHECK (agent_id <> '' AND agent_id = btrim(agent_id)),
 release_id text NOT NULL CHECK (release_id <> '' AND release_id = btrim(release_id)),
 session_id text NOT NULL CHECK (session_id <> '' AND session_id = btrim(session_id)),
 idempotency_key text NOT NULL CHECK (idempotency_key <> '' AND idempotency_key = btrim(idempotency_key)),
 request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
 status text NOT NULL CHECK (status IN ('PENDING','DISPATCHING','UNKNOWN','RECONCILING','ACCEPTED','REJECTED','MANUAL_REVIEW')),
 version bigint NOT NULL CHECK (version > 0),
 fence_token bigint NOT NULL DEFAULT 0 CHECK (fence_token >= 0),
 lease_owner text,
 lease_expires_at timestamptz,
 runtime_run_id text,
 workflow_id text,
 rejection_code text,
 manual_review_code text,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT run_intents_idempotency_unique UNIQUE (tenant_id, principal_id, operation, idempotency_key),
 CONSTRAINT run_intents_lease_consistency CHECK (
  (status IN ('DISPATCHING','RECONCILING') AND lease_owner IS NOT NULL AND lease_owner <> '' AND lease_expires_at IS NOT NULL AND fence_token > 0)
  OR (status NOT IN ('DISPATCHING','RECONCILING') AND lease_owner IS NULL AND lease_expires_at IS NULL)
 ),
 CONSTRAINT run_intents_state_payload_consistency CHECK (
  (status IN ('PENDING','DISPATCHING','UNKNOWN','RECONCILING') AND runtime_run_id IS NULL AND workflow_id IS NULL AND rejection_code IS NULL AND manual_review_code IS NULL)
  OR (status = 'ACCEPTED' AND runtime_run_id IS NOT NULL AND runtime_run_id <> '' AND runtime_run_id = btrim(runtime_run_id) AND length(runtime_run_id) <= 256 AND runtime_run_id !~ '[/#?]' AND workflow_id IS NOT NULL AND workflow_id = 'agent-run/v1/' || runtime_run_id AND rejection_code IS NULL AND manual_review_code IS NULL)
  OR (status = 'REJECTED' AND rejection_code IS NOT NULL AND rejection_code ~ '^[A-Z0-9_-]{1,128}$' AND runtime_run_id IS NULL AND workflow_id IS NULL AND manual_review_code IS NULL)
  OR (status = 'MANUAL_REVIEW' AND manual_review_code IS NOT NULL AND manual_review_code ~ '^[A-Z0-9_-]{1,128}$' AND runtime_run_id IS NULL AND workflow_id IS NULL AND rejection_code IS NULL)
 )
);
CREATE INDEX run_intents_dispatch_queue ON run_intents (created_at,id) WHERE status = 'PENDING';
CREATE INDEX run_intents_expired_lease ON run_intents (lease_expires_at,id) WHERE status IN ('DISPATCHING','RECONCILING');

CREATE TABLE outbox_events (
 event_id uuid PRIMARY KEY,
 producer text NOT NULL CHECK (producer <> ''),
 event_type text NOT NULL CHECK (event_type <> ''),
 schema_version integer NOT NULL CHECK (schema_version > 0),
 tenant_id text NOT NULL CHECK (tenant_id <> ''),
 aggregate_type text NOT NULL CHECK (aggregate_type <> ''),
 aggregate_id text NOT NULL CHECK (aggregate_id <> ''),
 aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
 occurred_at timestamptz NOT NULL,
 correlation_id text NOT NULL CHECK (correlation_id <> ''),
 causation_id text,
 traceparent text,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 delivery_state text NOT NULL DEFAULT 'PENDING' CHECK (delivery_state IN ('PENDING','PUBLISHING','PUBLISHED','QUARANTINED')),
 attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
 next_attempt_at timestamptz NOT NULL DEFAULT now(),
 lease_owner text,
 lease_expires_at timestamptz,
 published_at timestamptz,
 last_error_code text,
 created_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT outbox_aggregate_version_unique UNIQUE (producer,aggregate_type,aggregate_id,aggregate_version),
 CONSTRAINT outbox_lease_consistency CHECK (
  (delivery_state = 'PUBLISHING' AND lease_owner IS NOT NULL AND lease_owner <> '' AND lease_expires_at IS NOT NULL)
  OR (delivery_state <> 'PUBLISHING' AND lease_owner IS NULL AND lease_expires_at IS NULL)
 ),
 CONSTRAINT outbox_published_consistency CHECK (
  (delivery_state = 'PUBLISHED' AND published_at IS NOT NULL)
  OR (delivery_state <> 'PUBLISHED' AND published_at IS NULL)
 )
);
CREATE INDEX outbox_pending_delivery ON outbox_events (next_attempt_at,created_at) WHERE delivery_state = 'PENDING';
CREATE INDEX outbox_expired_publish_lease ON outbox_events (lease_expires_at) WHERE delivery_state = 'PUBLISHING';

CREATE TABLE inbox_events (
 consumer_name text NOT NULL CHECK (consumer_name <> ''),
 event_id uuid NOT NULL,
 producer text NOT NULL CHECK (producer <> ''),
 event_type text NOT NULL CHECK (event_type <> ''),
 schema_version integer NOT NULL CHECK (schema_version > 0),
 aggregate_type text NOT NULL CHECK (aggregate_type <> ''),
 aggregate_id text NOT NULL CHECK (aggregate_id <> ''),
 aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 state text NOT NULL CHECK (state IN ('RECEIVED','APPLIED','QUARANTINED')),
 received_at timestamptz NOT NULL DEFAULT now(),
 applied_at timestamptz,
 error_code text,
 PRIMARY KEY (consumer_name,event_id),
 CONSTRAINT inbox_applied_consistency CHECK (
  (state = 'APPLIED' AND applied_at IS NOT NULL AND error_code IS NULL)
  OR (state <> 'APPLIED' AND applied_at IS NULL)
 )
);
CREATE INDEX inbox_deferred_events ON inbox_events (consumer_name,aggregate_type,aggregate_id,aggregate_version) WHERE state = 'RECEIVED';

CREATE TABLE inbox_aggregate_claims (
 consumer_name text NOT NULL,
 aggregate_type text NOT NULL,
 aggregate_id text NOT NULL,
 aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
 event_id uuid NOT NULL,
 claimed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (consumer_name,aggregate_type,aggregate_id,aggregate_version),
 UNIQUE (consumer_name,event_id),
 FOREIGN KEY (consumer_name,event_id) REFERENCES inbox_events (consumer_name,event_id)
);
CREATE TABLE inbox_cursors (
 consumer_name text NOT NULL,
 aggregate_type text NOT NULL,
 aggregate_id text NOT NULL,
 last_applied_version bigint NOT NULL DEFAULT 0 CHECK (last_applied_version >= 0),
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (consumer_name,aggregate_type,aggregate_id)
);
COMMIT;
