-- Independent sandbox_journal_ci / Sandbox Service database ONLY.
-- Pre-Permit lease INTENT is not a provider SandboxLease or allocated resource.
BEGIN;
CREATE TABLE IF NOT EXISTS sandbox_lease_intents (
  tenant_id text NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128 AND tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  lease_intent_id text NOT NULL CHECK (length(lease_intent_id) BETWEEN 1 AND 128 AND lease_intent_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  run_id text NOT NULL CHECK (length(run_id) BETWEEN 1 AND 128 AND run_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  runtime_attempt_id text NOT NULL CHECK (length(runtime_attempt_id) BETWEEN 1 AND 128 AND runtime_attempt_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  state text NOT NULL DEFAULT 'WAITING_FOR_PERMIT',
  generation bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,lease_intent_id),
  CONSTRAINT sandbox_lease_intent_safe_states CHECK (
    (state = 'WAITING_FOR_PERMIT' AND generation = 1)
    OR (state = 'CANCELLED_BEFORE_PROVISION' AND generation = 2)
  )
);

CREATE TABLE IF NOT EXISTS sandbox_lease_intent_events (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id text NOT NULL,
  lease_intent_id text NOT NULL,
  generation bigint NOT NULL CHECK (generation IN (1,2)),
  event_type text NOT NULL,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,lease_intent_id,generation),
  CONSTRAINT sandbox_lease_intent_event_kind CHECK (
    (generation=1 AND event_type='sandbox.lease-intent.waiting-permit')
    OR (generation=2 AND event_type='sandbox.lease-intent.cancelled-before-provision')
  ),
  FOREIGN KEY (tenant_id,lease_intent_id) REFERENCES sandbox_lease_intents(tenant_id,lease_intent_id)
);
COMMIT;
