package lease

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func sampleIntent() Intent {
	return Intent{
		TenantID: "tenant-a", LeaseIntentID: "sandbox-intent-1",
		RunID:            "11111111-1111-4111-8111-111111111111",
		RuntimeAttemptID: "runtime-attempt-1",
		RequestDigest:    "sha256:" + strings.Repeat("a", 64),
	}
}

func testRepository(t *testing.T) *Repository {
	t.Helper()
	dsn := os.Getenv("SANDBOX_JOURNAL_TEST_DSN")
	if dsn == "" {
		t.Skip("independent Sandbox PostgreSQL DSN required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	raw, err := os.ReadFile(filepath.Join("..", "migrations", "0002_lease_intents.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(raw)); err != nil {
		t.Fatal("lease-intent migration:", err)
	}
	// Disposable owner-only test reset. After migration 0003, ordinary
	// TRUNCATE is forbidden; disabling the USER trigger for one rollback-safe
	// setup transaction must never be reproduced by the application writer.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	for _, sql := range []string{
		"ALTER TABLE sandbox_lease_intent_events DISABLE TRIGGER USER",
		"TRUNCATE sandbox_lease_intent_events,sandbox_lease_intents CASCADE",
		"ALTER TABLE sandbox_lease_intent_events ENABLE TRIGGER USER",
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal("isolated sandbox test reset:", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit isolated sandbox test reset:", err)
	}
	immutable, err := os.ReadFile(filepath.Join("..", "migrations", "0003_lease_outbox_immutable.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(immutable)); err != nil {
		t.Fatal("lease Outbox append-only migration:", err)
	}
	// RLS policies reference NOLOGIN group roles introduced in migration 0004.
	// Install the DBA-owned grant groups BEFORE attempting migration 0007;
	// a missing prerequisite must not be mistaken for an RLS behavior failure.
	rolePolicy, err := os.ReadFile(filepath.Join("..", "migrations", "0004_lease_runtime_roles.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(rolePolicy)); err != nil {
		t.Fatal("lease DBA role migration:", err)
	}
	// The independent CI database also installs the post-0005 deferrable
	// COMMIT constraint. Each test's owner-only reset remains disposable;
	// production runtime principals never execute migration SQL.
	commitGuard, err := os.ReadFile(filepath.Join("..", "migrations", "0006_lease_commit_integrity.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(commitGuard)); err != nil {
		t.Fatal("lease commit-integrity migration:", err)
	}
	// Tenant policy is installed by the owner, never through a runtime LOGIN.
	// Unbound logins are denied by default; real test users are bound only
	// after the DBA has provisioned their separate account credentials.
	rls, err := os.ReadFile(filepath.Join("..", "migrations", "0007_tenant_login_rls.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(rls)); err != nil {
		t.Fatal("tenant LOGIN RLS migration:", err)
	}
	// This owner-only migration NEVER rebinds existing LOGIN names to new
	// PostgreSQL role OIDs. A missing or stale OID remains fail-closed until
	// independently re-enrolled by a DBA.
	loginOIDFence, err := os.ReadFile(filepath.Join("..", "migrations", "0008_tenant_login_oid_fence.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(loginOIDFence)); err != nil {
		t.Fatal("tenant LOGIN role OID fencing migration:", err)
	}
	return New(pool)
}

func events(t *testing.T, repo *Repository) int {
	t.Helper()
	var n int
	if err := repo.pool.QueryRow(context.Background(), "SELECT count(*) FROM sandbox_lease_intent_events").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCreateIdempotentReopenAndDoNotProvision(t *testing.T) {
	repo := testRepository(t)
	ctx := context.Background()
	in := sampleIntent()
	got, created, err := repo.Create(ctx, in)
	if err != nil || !created || got.Intent != in || got.State != WaitingForPermit || got.Generation != 1 || got.CreatedAt.IsZero() {
		t.Fatalf("create: record=%+v created=%t err=%v", got, created, err)
	}
	again, created, err := repo.Create(ctx, in)
	if err != nil || created || again.Intent != in || again.State != WaitingForPermit || again.Generation != 1 || events(t, repo) != 1 {
		t.Fatalf("replay mutated state: record=%+v created=%t err=%v", again, created, err)
	}
	otherPool, err := pgxpool.New(ctx, os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer otherPool.Close()
	afterRestart, err := New(otherPool).Get(ctx, in.TenantID, in.LeaseIntentID)
	if err != nil || afterRestart.Intent != in || afterRestart.Generation != 1 || afterRestart.State != WaitingForPermit {
		t.Fatalf("reopened DB lost state: %+v %v", afterRestart, err)
	}
	for _, field := range []string{"SandboxUID", "ExecutorAttemptID", "ProviderResourceUID"} {
		if _, exists := reflect.TypeOf(Intent{}).FieldByName(field); exists {
			t.Fatalf("pre-Permit intent invented provisioned resource %s", field)
		}
	}
}

func TestCancelCASPersistsAndRejectsStaleGeneration(t *testing.T) {
	repo := testRepository(t)
	ctx := context.Background()
	in := sampleIntent()
	if _, _, err := repo.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	cancelled, err := repo.CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1)
	if err != nil || cancelled.Generation != 2 || cancelled.State != CancelledBeforeProvision || cancelled.Intent != in || events(t, repo) != 2 {
		t.Fatalf("cancel: %+v %v", cancelled, err)
	}
	for _, generation := range []uint64{1, 2, 0} {
		_, err := repo.CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, generation)
		if generation == 0 {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("zero generation accepted: %v", err)
			}
		} else if !errors.Is(err, ErrStaleGeneration) {
			t.Errorf("repeat or wrong generation accepted: gen=%d err=%v", generation, err)
		}
	}
	replayed, created, err := repo.Create(ctx, in)
	if err != nil || created || replayed.State != CancelledBeforeProvision || replayed.Generation != 2 || events(t, repo) != 2 {
		t.Fatalf("cancelled pre-provision intent was reopened: %+v %v", replayed, err)
	}
}

func TestConcurrentCancellationHasOneCASWinner(t *testing.T) {
	repo := testRepository(t)
	ctx := context.Background()
	in := sampleIntent()
	if _, _, err := repo.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	bad := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := repo.CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrStaleGeneration) {
				bad <- err
			}
		}()
	}
	wg.Wait()
	close(bad)
	for err := range bad {
		t.Errorf("unexpected CAS result: %v", err)
	}
	if wins.Load() != 1 || events(t, repo) != 2 {
		t.Fatalf("concurrent CAS successes=%d events=%d (want 1 and 2)", wins.Load(), events(t, repo))
	}
}

func TestCrossTenantAndDigestConflictsFailClosed(t *testing.T) {
	repo := testRepository(t)
	ctx := context.Background()
	in := sampleIntent()
	if _, _, err := repo.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Intent){
		func(x *Intent) { x.RequestDigest = "sha256:" + strings.Repeat("b", 64) },
		func(x *Intent) { x.RunID = "22222222-2222-4222-8222-222222222222" },
		func(x *Intent) { x.RuntimeAttemptID = "other-attempt" },
	} {
		conflict := in
		mutate(&conflict)
		if _, _, err := repo.Create(ctx, conflict); !errors.Is(err, ErrConflict) {
			t.Fatalf("rebound same lease intent accepted: %v", err)
		}
	}
	if _, err := repo.Get(ctx, "tenant-b", in.LeaseIntentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant saw intent: %v", err)
	}
	if _, err := repo.CancelBeforeProvision(ctx, "tenant-b", in.LeaseIntentID, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant cancelled intent: %v", err)
	}
	if events(t, repo) != 1 {
		t.Fatal("conflicting request emitted extra outbox event")
	}
}

func TestCancelOutboxErrorRollsBackGenerationAndCanRetry(t *testing.T) {
	repo := testRepository(t)
	ctx := context.Background()
	in := sampleIntent()
	if _, _, err := repo.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	_, err := repo.pool.Exec(ctx, "CREATE FUNCTION sandbox_lease_test_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected lease event failure'; END;$$")
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.pool.Exec(ctx, "CREATE TRIGGER sandbox_lease_test_fail BEFORE INSERT ON sandbox_lease_intent_events FOR EACH ROW EXECUTE FUNCTION sandbox_lease_test_fail()")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = repo.pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS sandbox_lease_test_fail ON sandbox_lease_intent_events")
		_, _ = repo.pool.Exec(context.Background(), "DROP FUNCTION IF EXISTS sandbox_lease_test_fail()")
	}()
	if _, err = repo.CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1); err == nil {
		t.Fatal("cancelled despite outbox write failure")
	}
	after, err := repo.Get(ctx, in.TenantID, in.LeaseIntentID)
	if err != nil || after.State != WaitingForPermit || after.Generation != 1 || events(t, repo) != 1 {
		t.Fatalf("outbox failure committed partial cancel: %+v %v", after, err)
	}
	_, _ = repo.pool.Exec(ctx, "DROP TRIGGER sandbox_lease_test_fail ON sandbox_lease_intent_events")
	_, _ = repo.pool.Exec(ctx, "DROP FUNCTION sandbox_lease_test_fail()")
	if _, err := repo.CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1); err != nil {
		t.Fatalf("rollback could not be safely retried: %v", err)
	}
	if events(t, repo) != 2 {
		t.Fatalf("expected only created+cancelled events, got %d", events(t, repo))
	}
}

func TestInvalidAndForgedProvisionStatesAreRejected(t *testing.T) {
	repo := testRepository(t)
	ctx := context.Background()
	in := sampleIntent()
	bad := in
	bad.RequestDigest = "md5:bad"
	if _, _, err := repo.Create(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid digest accepted: %v", err)
	}
	bad = in
	bad.LeaseIntentID = "bad id"
	if _, _, err := repo.Create(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid lease id accepted: %v", err)
	}
	if _, _, err := New(nil).Create(ctx, in); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil pool accepted: %v", err)
	}
	if _, _, err := repo.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.pool.Exec(ctx, "UPDATE sandbox_lease_intents SET state='PROVISIONED' WHERE tenant_id=$1 AND lease_intent_id=$2", in.TenantID, in.LeaseIntentID); err == nil {
		t.Fatal("DB constraint accepted fake provisioned resource")
	}
	if _, err := repo.pool.Exec(ctx, "UPDATE sandbox_lease_intents SET generation=9 WHERE tenant_id=$1 AND lease_intent_id=$2", in.TenantID, in.LeaseIntentID); err == nil {
		t.Fatal("DB constraint accepted invented generation")
	}
}
