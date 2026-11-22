-- 0014: append-only AgentD source-owned INSPECT journal. Not an OS
-- command dispatch, Guard Permit or provider release authority.
-- New table has no runtime grants, no non-owner RLS policy, and can only
-- be used through owner-controlled CI until real AgentD mTLS/PEP exists.
BEGIN;
CREATE TABLE IF NOT EXISTS public.sandbox_agentd_inspect_events (
  tenant_id text NOT NULL,
  sandbox_uid text NOT NULL,
  command_id text NOT NULL,
  attempt_id text NOT NULL,
  inspect_count bigint NOT NULL CHECK (inspect_count > 0),
  journal_version bigint NOT NULL CHECK (journal_version = inspect_count),
  payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 8192),
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  payload_digest text NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
  previous_digest text NOT NULL CHECK (
    previous_digest = '' OR previous_digest ~ '^sha256:[0-9a-f]{64}$'
  ),
  committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,sandbox_uid,command_id,attempt_id,inspect_count),
  FOREIGN KEY (tenant_id,sandbox_uid,command_id,attempt_id)
    REFERENCES public.sandbox_agentd_attempts(tenant_id,sandbox_uid,command_id,attempt_id)
);
DROP TRIGGER IF EXISTS agentd_inspect_no_update_delete ON public.sandbox_agentd_inspect_events;
CREATE TRIGGER agentd_inspect_no_update_delete
  BEFORE UPDATE OR DELETE ON public.sandbox_agentd_inspect_events
  FOR EACH ROW EXECUTE FUNCTION public.sandbox_agentd_deny_mutation();
ALTER TABLE public.sandbox_agentd_inspect_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sandbox_agentd_inspect_events FROM PUBLIC;
-- No RLS policy and no GRANT. Even a pre-Permit Command writer cannot
-- insert, replay or read trusted AgentD inspect events.
COMMIT;
