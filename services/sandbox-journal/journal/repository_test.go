package journal

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func sample() identity.Intent {
	return identity.Intent{
		TenantID: "tenant-a", RunID: "11111111-1111-4111-8111-111111111111", RuntimeAttemptID: "runtime-attempt-1",
		SandboxUID: "sandbox-uid-1", CommandID: "command-1", RequestDigest: "sha256:" + strings.Repeat("a", 64),
	}
}
func setup(t *testing.T) *Repository {
	t.Helper()
	url := os.Getenv("SANDBOX_JOURNAL_TEST_DSN")
	if url == "" {
		t.Skip("independent Sandbox PG DSN not configured")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	raw, err := os.ReadFile(filepath.Join("..", "migrations", "0001_command_journal.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(context.Background(), string(raw)); err != nil {
		t.Fatal("sandbox-only migration:", err)
	}
	// Disposable, owner-only test reset. Migration 0004 forbids ordinary
	// UPDATE/DELETE/TRUNCATE; tests must never use this DDL as a service API.
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	for _, statement := range []string{
		"ALTER TABLE sandbox_journal_outbox DISABLE TRIGGER USER",
		"ALTER TABLE sandbox_journal_commands DISABLE TRIGGER USER",
		"TRUNCATE sandbox_journal_outbox,sandbox_journal_commands CASCADE",
		"ALTER TABLE sandbox_journal_commands ENABLE TRIGGER USER",
		"ALTER TABLE sandbox_journal_outbox ENABLE TRIGGER USER",
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatal("isolated Journal test reset:", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit isolated Journal test reset:", err)
	}
	immutable, err := os.ReadFile(filepath.Join("..", "migrations", "0005_command_journal_outbox_immutable.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(immutable)); err != nil {
		t.Fatal("journal Outbox append-only migration:", err)
	}
	return New(pool)
}
func outboxCount(t *testing.T, repo *Repository) int {
	t.Helper()
	var n int
	if err := repo.pool.QueryRow(context.Background(), "SELECT count(*) FROM sandbox_journal_outbox").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func TestCommittedPermitUnavailableSurvivesReconnectAndOneOutbox(t *testing.T) {
	repo := setup(t)
	in := sample()
	record, created, err := repo.RecordPermitUnavailable(context.Background(), in)
	if err != nil || !created || record.State != PermitUnavailable || record.Generation != 1 || record.Identity != in {
		t.Fatalf("create: %+v %v %t", record, err, created)
	}
	again, created, err := repo.RecordPermitUnavailable(context.Background(), in)
	if err != nil || created || again != record {
		t.Fatalf("replay mutated: %+v %v %t", again, err, created)
	}
	if n := outboxCount(t, repo); n != 1 {
		t.Fatalf("outbox events=%d, want 1", n)
	}
	reconnected, err := pgxpool.New(context.Background(), os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer reconnected.Close()
	got, err := New(reconnected).Get(context.Background(), in.TenantID, in.SandboxUID, in.CommandID)
	if err != nil || got != record {
		t.Fatalf("reconnect lost receipt: %+v %v", got, err)
	}
}
func TestNoCrossTenantOrDigestConflictAndNoDuplicateEvent(t *testing.T) {
	repo := setup(t)
	in := sample()
	if _, _, err := repo.RecordPermitUnavailable(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	bad := in
	bad.RequestDigest = "sha256:" + strings.Repeat("b", 64)
	if _, _, err := repo.RecordPermitUnavailable(context.Background(), bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed digest accepted: %v", err)
	}
	bad = in
	bad.RunID = "22222222-2222-4222-8222-222222222222"
	if _, _, err := repo.RecordPermitUnavailable(context.Background(), bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed Run accepted: %v", err)
	}
	bad = in
	bad.RuntimeAttemptID = "runtime-attempt-2" // same command cannot change Runtime Attempt
	if _, _, err := repo.RecordPermitUnavailable(context.Background(), bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed Runtime Attempt accepted: %v", err)
	}
	if _, err := repo.Get(context.Background(), "tenant-b", in.SandboxUID, in.CommandID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant row exposed: %v", err)
	}
	if n := outboxCount(t, repo); n != 1 {
		t.Fatalf("conflicts emitted duplicate events: %d", n)
	}
}
func TestConcurrentDuplicateSubmissionsCreateExactlyOneJournalAndOutbox(t *testing.T) {
	repo := setup(t)
	in := sample()
	var count atomic.Int64
	var wg sync.WaitGroup
	errCh := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, created, err := repo.RecordPermitUnavailable(context.Background(), in)
			if err != nil {
				errCh <- err
				return
			}
			if created {
				count.Add(1)
			}
			if rec.Identity != in || rec.State != PermitUnavailable {
				errCh <- errors.New("invalid replay result")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if count.Load() != 1 || outboxCount(t, repo) != 1 {
		t.Fatalf("concurrent replay created=%d outbox=%d", count.Load(), outboxCount(t, repo))
	}
}
func TestOutboxFailureRollsBackJournal(t *testing.T) {
	repo := setup(t)
	ctx := context.Background()
	_, err := repo.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION sandbox_test_reject_event() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test outbox failure'; END;$$`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.pool.Exec(ctx, `CREATE TRIGGER sandbox_test_fail BEFORE INSERT ON sandbox_journal_outbox FOR EACH ROW EXECUTE FUNCTION sandbox_test_reject_event()`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = repo.pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS sandbox_test_fail ON sandbox_journal_outbox")
		_, _ = repo.pool.Exec(context.Background(), "DROP FUNCTION IF EXISTS sandbox_test_reject_event()")
	}()
	in := sample()
	if _, _, err = repo.RecordPermitUnavailable(ctx, in); err == nil {
		t.Fatal("outbox failure did not abort transaction")
	}
	if _, err = repo.Get(ctx, in.TenantID, in.SandboxUID, in.CommandID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("journal committed without outbox: %v", err)
	}
}
func TestInvalidRequestNeverWrites(t *testing.T) {
	repo := setup(t)
	in := sample()
	in.CommandID = ""
	if _, _, err := repo.RecordPermitUnavailable(context.Background(), in); !errors.Is(err, identity.ErrInvalid) {
		t.Fatalf("invalid command was accepted: %v", err)
	}
	if n := outboxCount(t, repo); n != 0 {
		t.Fatalf("invalid write emitted outbox: %d", n)
	}
	if _, _, err := New(nil).RecordPermitUnavailable(context.Background(), sample()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil pool accepted: %v", err)
	}
}

func TestReplayRefusesCorruptOrMissingCommittedOutbox(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper string
	}{
		{"missing_event", "DELETE FROM sandbox_journal_outbox"},
		{"changed_original_run", `UPDATE sandbox_journal_outbox SET payload=jsonb_set(payload,'{run_id}','"different-run"'::jsonb)`},
		{"changed_attempt", `UPDATE sandbox_journal_outbox SET payload=jsonb_set(payload,'{runtime_attempt_id}','"other-attempt"'::jsonb)`},
		{"changed_digest", `UPDATE sandbox_journal_outbox SET payload=jsonb_set(payload,'{request_digest}','"sha256:0000000000000000000000000000000000000000000000000000000000000000"'::jsonb)`},
		{"unexpected_sensitive_field", `UPDATE sandbox_journal_outbox SET payload=jsonb_set(payload,'{raw_bearer_token}',to_jsonb('not-an-authorized-field'::text))`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := setup(t)
			in := sample()
			if _, created, err := repo.RecordPermitUnavailable(context.Background(), in); err != nil || !created {
				t.Fatalf("initial atomic command+outbox: created=%v err=%v", created, err)
			}
			// Only the disposable PostgreSQL owner may bypass the immutable
			// trigger for a historical-corruption negative test.
			injectPreexistingJournalCorruption(t, repo, tc.tamper)
			if _, created, err := repo.RecordPermitUnavailable(context.Background(), in); created || !errors.Is(err, ErrCorrupt) {
				t.Fatalf("replay promoted corrupt outbox: created=%v err=%v", created, err)
			}
			if _, err := repo.Get(context.Background(), in.TenantID, in.SandboxUID, in.CommandID); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Get accepted disconnected/corrupt outbox: %v", err)
			}
		})
	}
}

// Test-only OS subprocess, never an AgentD executor or Guard Permit fixture.
// It persists a rejection fact, then waits to be SIGKILLed after the SQL commit.
func TestSandboxJournalCrashChild(t *testing.T) {
	mode := os.Getenv("SANDBOX_JOURNAL_CHILD_MODE")
	if mode == "" {
		return
	}
	dsn := os.Getenv("SANDBOX_JOURNAL_TEST_DSN")
	if dsn == "" {
		t.Fatal("child has no independent Sandbox DB")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repo := New(pool)
	in := sample()
	switch mode {
	case "write":
		_, created, err := repo.RecordPermitUnavailable(context.Background(), in)
		if err != nil || !created {
			t.Fatalf("child commit: created=%t err=%v", created, err)
		}
		fmt.Println("COMMITTED")
		time.Sleep(time.Minute)
		t.Fatal("expected parent to SIGKILL the committed child")
	case "inspect":
		got, err := repo.Get(context.Background(), in.TenantID, in.SandboxUID, in.CommandID)
		if err != nil || got.Identity != in || got.State != PermitUnavailable {
			t.Fatalf("fresh process could not inspect committed command: %v", err)
		}
		if _, created, err := repo.RecordPermitUnavailable(context.Background(), in); err != nil || created {
			t.Fatalf("fresh process replay: created=%v err=%v", created, err)
		}
		var count int
		if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM sandbox_journal_outbox").Scan(&count); err != nil || count != 1 {
			t.Fatalf("fresh process duplicate/missing outbox: %d %v", count, err)
		}
		fmt.Println("REPLAY_OK")
	default:
		t.Fatal("unknown subprocess mode")
	}
}

func TestSIGKILLAfterCommitFreshProcessReconcilesWithoutDispatch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SIGKILL process-status assertion requires Linux")
	}
	repo := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	writer := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSandboxJournalCrashChild$", "-test.timeout=25s")
	writer.Env = append(os.Environ(), "SANDBOX_JOURNAL_CHILD_MODE=write")
	stdout, err := writer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if writer.ProcessState == nil {
			_ = writer.Process.Kill()
			_ = writer.Wait()
		}
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "COMMITTED\n" {
		t.Fatalf("child did not prove commit before SIGKILL: line=%q err=%v", line, err)
	}
	if err := writer.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	waitErr := writer.Wait()
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		t.Fatalf("expected actual child SIGKILL, got %v", waitErr)
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("did not observe SIGKILL termination: %v", exitErr.Sys())
	}
	// A brand-new process reopens PostgreSQL and must not mint another row
	// or outbox. There is NO dispatched/UNKNOWN command in this experiment.
	inspector := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSandboxJournalCrashChild$", "-test.timeout=15s")
	inspector.Env = append(os.Environ(), "SANDBOX_JOURNAL_CHILD_MODE=inspect")
	result, err := inspector.CombinedOutput()
	if err != nil || !strings.Contains(string(result), "REPLAY_OK") {
		t.Fatalf("independent fresh-process replay failed: %v: %s", err, result)
	}
	if count := outboxCount(t, repo); count != 1 {
		t.Fatalf("replayed command produced multiple outbox facts: %d", count)
	}
}
