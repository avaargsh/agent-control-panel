-- Disposable Docker Compose demo only: public test credentials, NEVER deploy.
-- sandboxctl must use a SELECT-only DB principal, not the migration owner.
CREATE ROLE sandbox_demo_reader LOGIN PASSWORD 'demo-reader-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE sandbox_demo TO sandbox_demo_reader;
GRANT USAGE ON SCHEMA public TO sandbox_demo_reader;
GRANT SELECT ON sandbox_lease_intents, sandbox_journal_commands TO sandbox_demo_reader;
