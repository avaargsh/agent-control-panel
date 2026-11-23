-- 0013: AgentD-owned authoritative attempt/terminal evidence candidate.
-- Independent Sandbox database ONLY. Does not authorize command dispatch.
-- Tables are owner-only (no runtime INSERT/SELECT grants) pending real Guard
-- mTLS issuer+PEP integration and independent least-privilege role review.
BEGIN;
CREATE TABLE IF NOT EXISTS public.sandbox_agentd_attempts (
  tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  run_id text NOT NULL CHECK (run_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  runtime_attempt_id text NOT NULL CHECK (runtime_attempt_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  sandbox_uid text NOT NULL CHECK (sandbox_uid ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  command_id text NOT NULL CHECK (command_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  attempt_id text NOT NULL CHECK (attempt_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  provider_command_uid text NOT NULL CHECK (provider_command_uid ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  guard_permit_id text NOT NULL CHECK (guard_permit_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  permit_epoch bigint NOT NULL CHECK (permit_epoch > 0),
  process_pid integer NOT NULL CHECK (process_pid > 0),
  process_start_ticks bigint NOT NULL CHECK (process_start_ticks > 0),
  host_boot_id text NOT NULL CHECK (host_boot_id ~ '^[0-9a-f-]{36}$'),
  dispatch_count integer NOT NULL DEFAULT 1 CHECK (dispatch_count = 1),
  status text NOT NULL DEFAULT 'UNKNOWN' CHECK (status = 'UNKNOWN'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,sandbox_uid,command_id,attempt_id),
  -- Attempt identity cannot be swapped to silently dispatch a second process.
  UNIQUE(tenant_id,sandbox_uid,command_id),
  UNIQUE(tenant_id,provider_command_uid)
);
CREATE TABLE IF NOT EXISTS public.sandbox_agentd_terminal_receipts (
  tenant_id text NOT NULL,
  sandbox_uid text NOT NULL,
  command_id text NOT NULL,
  attempt_id text NOT NULL,
  payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 8192),
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  payload_digest text NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
  committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,sandbox_uid,command_id,attempt_id),
  FOREIGN KEY(tenant_id,sandbox_uid,command_id,attempt_id)
    REFERENCES public.sandbox_agentd_attempts(tenant_id,sandbox_uid,command_id,attempt_id)
);
CREATE OR REPLACE FUNCTION public.sandbox_agentd_deny_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public
AS $$
BEGIN
  RAISE EXCEPTION 'AgentD original attempt/terminal evidence is append-only'
    USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS agentd_attempt_no_update_delete ON public.sandbox_agentd_attempts;
CREATE TRIGGER agentd_attempt_no_update_delete
  BEFORE UPDATE OR DELETE ON public.sandbox_agentd_attempts
  FOR EACH ROW EXECUTE FUNCTION public.sandbox_agentd_deny_mutation();
DROP TRIGGER IF EXISTS agentd_terminal_no_update_delete ON public.sandbox_agentd_terminal_receipts;
CREATE TRIGGER agentd_terminal_no_update_delete
  BEFORE UPDATE OR DELETE ON public.sandbox_agentd_terminal_receipts
  FOR EACH ROW EXECUTE FUNCTION public.sandbox_agentd_deny_mutation();

ALTER TABLE public.sandbox_agentd_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sandbox_agentd_terminal_receipts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sandbox_agentd_attempts,public.sandbox_agentd_terminal_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sandbox_agentd_deny_mutation() FROM PUBLIC;
-- The tables have no non-owner policies: even a pre-Permit Command writer
-- or read-only sandboxctl principal MUST NOT mint/inspect AgentD terminal proof.
COMMIT;
