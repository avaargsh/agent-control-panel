-- Run ONLY on the independent Sandbox Journal database, never the ACP DB.
-- Deliberately no transition to DISPATCHING: trusted Guard Permit/PEP is absent.
BEGIN;
CREATE TABLE IF NOT EXISTS sandbox_journal_commands (
  tenant_id text NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128 AND tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  sandbox_uid text NOT NULL CHECK (length(sandbox_uid) BETWEEN 1 AND 128 AND sandbox_uid ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  command_id text NOT NULL CHECK (length(command_id) BETWEEN 1 AND 128 AND command_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  run_id text NOT NULL CHECK (length(run_id) BETWEEN 1 AND 128 AND run_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  runtime_attempt_id text NOT NULL CHECK (length(runtime_attempt_id) BETWEEN 1 AND 128 AND runtime_attempt_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation = 1),
  state text NOT NULL DEFAULT 'PERMIT_UNAVAILABLE' CHECK (state = 'PERMIT_UNAVAILABLE'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, sandbox_uid, command_id)
);
CREATE TABLE IF NOT EXISTS sandbox_journal_outbox (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id text NOT NULL,
  sandbox_uid text NOT NULL,
  command_id text NOT NULL,
  generation bigint NOT NULL CHECK (generation = 1),
  event_type text NOT NULL CHECK (event_type = 'sandbox.command.permit-unavailable'),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,sandbox_uid,command_id,generation),
  FOREIGN KEY (tenant_id,sandbox_uid,command_id)
    REFERENCES sandbox_journal_commands (tenant_id,sandbox_uid,command_id)
);
COMMIT;
