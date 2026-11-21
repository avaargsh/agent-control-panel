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
