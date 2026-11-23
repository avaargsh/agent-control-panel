-- CI-only fixture: logical pre-Permit lease and denied command.
-- It must never be run against a production or shared database.
BEGIN;
INSERT INTO sandbox_lease_intents
(tenant_id, lease_intent_id, run_id, runtime_attempt_id, request_digest)
VALUES ('sandboxctl-smoke', 'lease-smoke-1', 'run-smoke-1', 'runtime-smoke-1',
'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
INSERT INTO sandbox_lease_intent_events
(tenant_id, lease_intent_id, generation, event_type, payload)
VALUES ('sandboxctl-smoke', 'lease-smoke-1', 1,
'sandbox.lease-intent.waiting-permit', '{"run_id":"run-smoke-1","runtime_attempt_id":"runtime-smoke-1","request_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'::jsonb);
INSERT INTO sandbox_journal_commands
(tenant_id, sandbox_uid, command_id, run_id, runtime_attempt_id, request_digest)
VALUES ('sandboxctl-smoke', 'sandbox-smoke-1', 'command-smoke-1', 'run-smoke-1', 'runtime-smoke-1',
'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
INSERT INTO sandbox_journal_outbox
(tenant_id, sandbox_uid, command_id, generation, event_type, payload)
VALUES ('sandboxctl-smoke', 'sandbox-smoke-1', 'command-smoke-1', 1,
'sandbox.command.permit-unavailable', '{"run_id":"run-smoke-1","runtime_attempt_id":"runtime-smoke-1","request_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'::jsonb);
COMMIT;
