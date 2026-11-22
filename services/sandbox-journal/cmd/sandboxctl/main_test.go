package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestOperatorOutputsShowDenialsAndNoSensitiveRequestDigests(t *testing.T) {
	leases, commands, query := exampleReaders()
	report, err := inspect(t.Context(), query, leases, commands)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"text", "json"} {
		var out bytes.Buffer
		if err := renderReport(&out, report, format); err != nil {
			t.Fatal(err)
		}
		body := out.String()
		if strings.Contains(body, strings.Repeat("a", 64)) || strings.Contains(body, strings.Repeat("b", 64)) {
			t.Fatalf("request digest leaked in %s output", format)
		}
		if format == "text" {
			for _, text := range []string{"UNATTESTED", "WAITING_FOR_PERMIT", "PERMIT_UNAVAILABLE", "Dispatch: DENIED", "Release: UNVERIFIED"} {
				if !strings.Contains(body, text) {
					t.Fatalf("missing safe hint %q in %s", text, body)
				}
			}
			continue
		}
		var decoded Report
		if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.NextAction != "HOLD" || decoded.CanDispatch || decoded.CanRetry ||
			decoded.CanDeclareSuccess || decoded.CanDeclareReleased {
			t.Fatalf("unsafe JSON report: %+v", decoded)
		}
	}
}

func TestOperatorRejectsUnsafeFlagsAndNeverPrintsDatabaseDSN(t *testing.T) {
	t.Setenv("SANDBOX_JOURNAL_READ_DSN", "postgres://a-secret-user:a-secret-password@invalid:5432/secret")
	bad := [][]string{
		nil, {"execute"}, {"inspect"}, {"inspect", "--tenant", "tenant-a"},
		{"inspect", "--tenant", "tenant-a", "--lease-intent", "bad id"},
		{"inspect", "--tenant", "tenant-a", "--lease-intent", "lease-1", "--format", "unsafe"},
		{"inspect", "--tenant", "tenant-a", "--lease-intent", "lease-1", "extra-argument"},
		{"inspect", "--tenant", "tenant-a", "--lease-intent", "lease-1", "--permit", "fake"},
	}
	for _, args := range bad {
		var stdout, stderr bytes.Buffer
		exit := run(args, &stdout, &stderr)
		if exit != 2 || stdout.Len() != 0 ||
			strings.Contains(stderr.String(), "a-secret-password") ||
			strings.Contains(stderr.String(), "a-secret-user") {
			t.Fatalf("unsafe or leaked input %v: exit %d stdout=%q stderr=%q", args, exit, stdout.String(), stderr.String())
		}
	}
	t.Setenv("SANDBOX_JOURNAL_READ_DSN", "")
	var stdout, stderr bytes.Buffer
	exit := run([]string{"inspect", "--tenant", "tenant-a", "--lease-intent", "lease-1"}, &stdout, &stderr)
	if exit != 3 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "READ_SOURCE_UNAVAILABLE") {
		t.Fatalf("missing DB was accepted: %d %q", exit, stderr.String())
	}
}

func TestSandboxctlRejectsPrivilegedDatabaseIdentityBeforeReading(t *testing.T) {
	dsn := os.Getenv("SANDBOX_JOURNAL_TEST_DSN")
	if dsn == "" {
		t.Skip("real independent Sandbox PostgreSQL role gate requires CI database")
	}
	// The CI migration owner is also a writable PostgreSQL principal.
	// A session default_transaction_read_only=on must NOT turn that
	// credential into acceptable read-only diagnostic authority.
	t.Setenv("SANDBOX_JOURNAL_READ_DSN", dsn)
	var stdout, stderr bytes.Buffer
	exit := run([]string{"inspect", "--tenant", "tenant-scope-a",
		"--lease-intent", "missing-lease"}, &stdout, &stderr)
	if exit != 3 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "READ_SOURCE_UNAVAILABLE") ||
		strings.Contains(stderr.String(), "UNVERIFIED") ||
		strings.Contains(stderr.String(), "sandbox-test-only") {
		t.Fatalf("writable DB credential was treated as read-only: exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}
