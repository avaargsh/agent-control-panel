-- Disposable Docker Compose demo only: public test credentials, NEVER deploy.
-- sandboxctl must use a SELECT-only DB principal, not the migration owner.
CREATE ROLE sandbox_demo_reader LOGIN PASSWORD 'demo-reader-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE sandbox_demo TO sandbox_demo_reader;
GRANT USAGE ON SCHEMA public TO sandbox_demo_reader;
GRANT SELECT ON sandbox_lease_intents, sandbox_journal_commands,
  sandbox_lease_intent_events, sandbox_journal_outbox TO sandbox_demo_reader;

-- Disposable operator is bound to exactly one RLS-protected lease tenant.
GRANT acp_sandbox_lease_reader TO sandbox_demo_reader;
INSERT INTO public.sandbox_lease_db_principals(login_name,tenant_id)
VALUES ('sandbox_demo_reader','sandboxctl-smoke');
