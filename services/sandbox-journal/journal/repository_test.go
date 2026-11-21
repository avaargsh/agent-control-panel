package journal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func sample() identity.Intent {
	return identity.Intent{
		TenantID: "tenant-a", RunID: "11111111-1111-4111-8111-111111111111", RuntimeAttemptID: "runtime-attempt-1",
		SandboxUID: "sandbox-uid-1", CommandID: "command-1", ExecutorAttemptID: "exec-attempt-1", RequestDigest: "sha256:" + strings.Repeat("a", 64),
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
	if _, err = pool.Exec(context.Background(), "TRUNCATE sandbox_journal_outbox,sandbox_journal_commands CASCADE"); err != nil {
		t.Fatal(err)
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
	bad.CommandID = "command-2" // same executor attempt cannot be rebound
	if _, _, err := repo.RecordPermitUnavailable(context.Background(), bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused executor attempt accepted: %v", err)
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
