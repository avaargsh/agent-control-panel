// sandboxctl is a local-only, read-only developer inspection command.
// It is NOT an authenticated production API, Permit issuer or executor.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/journal"
	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/lease"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "inspect" {
		fmt.Fprintln(stderr, "Usage: sandboxctl inspect --tenant TENANT [--lease-intent ID] [--sandbox-uid UID --command-id ID] [--format text|json]")
		return 2
	}
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant scope (NOT an authorization credential)")
	intent := fs.String("lease-intent", "", "pre-Permit lease-intent ID")
	sandboxUID := fs.String("sandbox-uid", "", "existing sandbox UID reference")
	commandID := fs.String("command-id", "", "pre-Permit command ID")
	format := fs.String("format", "text", "text or json")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || (*format != "text" && *format != "json") {
		fmt.Fprintln(stderr, "INVALID_QUERY: only inspect flags and text|json are accepted")
		return 2
	}
	query := Query{TenantID: *tenant, LeaseIntentID: *intent, SandboxUID: *sandboxUID, CommandID: *commandID}
	if !validQuery(query) {
		fmt.Fprintln(stderr, "INVALID_QUERY: specify tenant and lease-intent, command references, or both")
		return 2
	}
	dsn := os.Getenv("SANDBOX_JOURNAL_READ_DSN")
	if dsn == "" {
		fmt.Fprintln(stderr, "READ_SOURCE_UNAVAILABLE: configure SANDBOX_JOURNAL_READ_DSN (separate sandbox DB)")
		return 3
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		fmt.Fprintln(stderr, "READ_SOURCE_UNAVAILABLE: invalid read database configuration")
		return 3
	}
	// Enforce read-only default transactions in addition to exposing no
	// mutation paths. Use a separately provisioned SELECT-only DB role.
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	// Ignore caller-controlled URL options and role defaults for object lookup.
	// Pin the real Sandbox tables before pg_temp or any attacker schema.
	cfg.ConnConfig.RuntimeParams["search_path"] = "pg_catalog,public,pg_temp"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		fmt.Fprintln(stderr, "READ_SOURCE_UNAVAILABLE: cannot open sandbox read database")
		return 3
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintln(stderr, "READ_SOURCE_UNAVAILABLE: sandbox read database cannot be reached")
		return 3
	}
	if err := verifySandboxReadRole(ctx, pool); err != nil {
		fmt.Fprintln(stderr, "READ_SOURCE_UNAVAILABLE: database identity is not a least-privileged reader")
		return 3
	}
	result, err := inspect(ctx, query, lease.New(pool), journal.New(pool))
	if err != nil {
		if errors.Is(err, ErrBadQuery) {
			fmt.Fprintln(stderr, "INVALID_QUERY")
			return 2
		}
		fmt.Fprintln(stderr, "UNVERIFIED: no trusted status conclusion; check source, tenant, Run and attempt")
		return 3
	}
	if err := renderReport(stdout, result, *format); err != nil {
		fmt.Fprintln(stderr, "OUTPUT_UNAVAILABLE: could not render status")
		return 3
	}
	return 0
}

// verifySandboxReadRole checks server-side grants, not application-local
// transaction flags. The initial session principal must have SELECT on the
// exact Sandbox-owned read surfaces but no mutation/DDL/role-escalation rights.
// Always resolve role permissions against source-owned public tables, never
// unqualified regclass names from a client-supplied PostgreSQL search_path.
// This is a local operator credential safety gate, NOT tenant authentication,
// Sandbox lease authority, or proof of an externally trusted provider.
func verifySandboxReadRole(ctx context.Context, pool *pgxpool.Pool) error {
	const query = `
		SELECT current_user = session_user
		  AND has_schema_privilege(current_user, 'public', 'USAGE')
		  AND has_table_privilege(current_user, 'public.sandbox_lease_intents'::regclass, 'SELECT')
		  AND has_table_privilege(current_user, 'public.sandbox_journal_commands'::regclass, 'SELECT')
		  AND has_table_privilege(current_user, 'public.sandbox_lease_intent_events'::regclass, 'SELECT')
		  AND has_table_privilege(current_user, 'public.sandbox_journal_outbox'::regclass, 'SELECT')
		  -- PostgreSQL Sequence ACLs are separate from table ACLs.
		  -- USAGE/UPDATE may advance a persisted sequence even without
		  -- table DML. This command accepts ONLY SELECT on four journal
		  -- tables, never unrelated sequence rights or PUBLIC grants.
		  AND NOT EXISTS (
		    SELECT 1 FROM pg_catalog.pg_class c
		    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		    WHERE c.relkind = 'S'
		      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		      AND n.nspname NOT LIKE 'pg_toast%'
		      AND n.nspname NOT LIKE 'pg_temp_%'
		      -- WHERE reordering must never call this function on a table.
		      AND CASE WHEN c.relkind = 'S'
		               THEN has_sequence_privilege(current_user, c.oid, 'SELECT,USAGE,UPDATE')
		               ELSE false END
		  )
		  -- A function created by the DB owner may carry SECURITY
		  -- DEFINER + default PUBLIC EXECUTE. An otherwise SELECT-only
		  -- LOGIN with schema USAGE can invoke it to read/write data under
		  -- the owner's privilege. Fail closed on effective callable
		  -- routines in any non-system schema, not only journal tables.
		  -- PostgreSQL trigger-only functions cannot be called directly
		  -- via SELECT/CALL; excluding their return type preserves the
		  -- verified commit-history constraint triggers in migration 0006.
		  AND NOT EXISTS (
		    SELECT 1
		      FROM pg_catalog.pg_proc f
		      JOIN pg_catalog.pg_namespace n ON n.oid = f.pronamespace
		     WHERE f.prosecdef
		       AND f.prorettype <> 'pg_catalog.trigger'::regtype
		       AND f.prorettype <> 'pg_catalog.event_trigger'::regtype
		       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		       AND n.nspname NOT LIKE 'pg_toast%'
		       AND n.nspname NOT LIKE 'pg_temp_%'
		       AND has_schema_privilege(current_user, n.oid, 'USAGE')
		       AND has_function_privilege(current_user, f.oid, 'EXECUTE')
		       -- Migration 0007 intentionally uses exactly this DBA-owned
		       -- stable SQL helper to bind the authenticated session LOGIN
		       -- to its lease tenant. Do not broadly allow a function name:
		       -- require its signature, language, owner of the private
		       -- binding table and pinned search_path to agree. Table owner
		       -- compromise remains outside the operator reader trust model.
		       AND NOT (
		         n.nspname = 'public'
		         AND f.proname = 'sandbox_bound_lease_tenant'
		         AND f.pronargs = 0
		         AND f.prorettype = 'pg_catalog.text'::regtype
		         AND f.provolatile = 's'
		         AND f.prolang = (
		           SELECT l.oid FROM pg_catalog.pg_language l
		            WHERE l.lanname = 'sql'
		         )
		         AND 'search_path=pg_catalog, public' = ANY(f.proconfig)
		         AND EXISTS (
		           SELECT 1
		             FROM pg_catalog.pg_class binding
		             JOIN pg_catalog.pg_namespace bn ON bn.oid = binding.relnamespace
		            WHERE bn.nspname = 'public'
		              AND binding.relname = 'sandbox_lease_db_principals'
		              AND binding.relkind = 'r'
		              AND binding.relowner = f.proowner
		         )
		       )
		  )
		  AND NOT EXISTS (
		    SELECT 1 FROM pg_roles AS r
		    WHERE (r.rolname = session_user OR pg_has_role(session_user, r.oid, 'MEMBER'))
		      AND (
		        r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
		        OR r.rolname IN ('pg_read_all_data', 'pg_write_all_data', 'pg_monitor')
		        OR has_database_privilege(r.oid, current_database(), 'CREATE')
		        OR has_schema_privilege(r.oid, 'public', 'CREATE')
		        OR has_table_privilege(r.oid, 'public.sandbox_lease_intents'::regclass, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
		        OR has_table_privilege(r.oid, 'public.sandbox_journal_commands'::regclass, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
		        OR has_table_privilege(r.oid, 'public.sandbox_lease_intent_events'::regclass, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
		        OR has_table_privilege(r.oid, 'public.sandbox_journal_outbox'::regclass, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
		        OR has_any_column_privilege(r.oid, 'public.sandbox_lease_intents'::regclass, 'INSERT,UPDATE,REFERENCES')
		        OR has_any_column_privilege(r.oid, 'public.sandbox_journal_commands'::regclass, 'INSERT,UPDATE,REFERENCES')
		        OR has_any_column_privilege(r.oid, 'public.sandbox_lease_intent_events'::regclass, 'INSERT,UPDATE,REFERENCES')
		        OR has_any_column_privilege(r.oid, 'public.sandbox_journal_outbox'::regclass, 'INSERT,UPDATE,REFERENCES')
		      )
		  )
	`
	var allowed bool
	if err := pool.QueryRow(ctx, query).Scan(&allowed); err != nil || !allowed {
		return errors.New("sandbox reader credential violates server-side least privilege")
	}
	return nil
}

func renderReport(w io.Writer, report Report, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	if format != "text" {
		return ErrBadQuery
	}
	if _, err := fmt.Fprintf(w, "Sandbox status (UNATTESTED local DB snapshot)\nTenant: %s\n", report.TenantID); err != nil {
		return err
	}
	if report.Lease != nil {
		if _, err := fmt.Fprintf(w, "Lease intent: %s | %s | generation %d\n", report.Lease.LeaseIntentID, report.Lease.State, report.Lease.Generation); err != nil {
			return err
		}
	}
	if report.Command != nil {
		if _, err := fmt.Fprintf(w, "Command: %s | %s | generation %d\n", report.Command.CommandID, report.Command.State, report.Command.Generation); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "Next: %s\nDispatch: DENIED | Retry: DENIED | Success: UNVERIFIED | Release: UNVERIFIED\n", report.NextAction)
	return err
}
