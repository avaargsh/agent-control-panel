-- Disposable Docker Compose demo only: public test credentials, NEVER deploy.
-- sandboxctl must use a SELECT-only DB principal, not the migration owner.
CREATE ROLE sandbox_demo_reader LOGIN PASSWORD 'demo-reader-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE sandbox_demo TO sandbox_demo_reader;
GRANT USAGE ON SCHEMA public TO sandbox_demo_reader;
-- Command and lease are independently authorized by owner-managed groups.
-- No direct command table ACL should substitute for the RLS tenant policy.
GRANT acp_sandbox_command_reader TO sandbox_demo_reader;

-- Disposable operator is bound to exactly one OID-fenced Sandbox tenant.
GRANT acp_sandbox_lease_reader TO sandbox_demo_reader;
INSERT INTO public.sandbox_lease_db_principals(login_name,tenant_id)
VALUES ('sandbox_demo_reader','sandboxctl-smoke');
