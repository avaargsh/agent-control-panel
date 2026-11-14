package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/researchlock"
)

func pinnedFixture(intentID string) researchlock.Lock {
	return researchlock.Lock{
		TenantID: "tenant-integration", PrincipalID: "principal-integration", RunIntentID: intentID,
		AgentReleaseID: "release-1", WorkspaceID: "workspace-1", SessionID: "session-1",
		PackageID: "equity-research", Version: "1.2.0",
		ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
		SubscriptionID: "subscription-1", PolicyRevision: "policy-1",
	}
}

func TestCreatePinnedAtomicReplayAndRollback(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(9701)
	lock := pinnedFixture(intent.ID)
	created, inserted, err := repository.CreatePinned(ctx, intent, testEvent(intent, 1, 9711, eventCreated), lock)
	if err != nil || !inserted || created.ID != intent.ID {
		t.Fatalf("pinned create: inserted=%v intent=%+v err=%v", inserted, created, err)
	}
	got, err := repository.GetCapabilityLock(ctx, intent.TenantID, intent.ID)
	if err != nil || got != lock {
		t.Fatalf("read pinned lock: got=%+v err=%v", got, err)
	}
	retry := intent
	retry.ID = testIntent(9702).ID
	replayLock := lock
	replayLock.RunIntentID = retry.ID
	replayed, inserted, err := repository.CreatePinned(ctx, retry, testEvent(retry, 1, 9712, eventCreated), replayLock)
	if err != nil || inserted || replayed.ID != created.ID {
		t.Fatalf("idempotent pinned replay: inserted=%v intent=%+v err=%v", inserted, replayed, err)
	}
	if got := countOutbox(t, pool, intent.ID); got != 1 {
		t.Fatalf("replay emitted %d Outbox records", got)
	}
	replayLock.WorkspaceID = "workspace-other"
	if _, _, err := repository.CreatePinned(ctx, retry, testEvent(retry, 1, 9713, eventCreated), replayLock); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed Workspace silently replayed: %v", err)
	}
	replayLock = lock
	replayLock.RunIntentID = retry.ID
	replayLock.ArtifactDigest = "sha256:" + strings.Repeat("b", 64)
	if _, _, err := repository.CreatePinned(ctx, retry, testEvent(retry, 1, 9714, eventCreated), replayLock); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed DAS digest silently replayed: %v", err)
	}
	if _, _, err := repository.Create(ctx, retry, testEvent(retry, 1, 9715, eventCreated)); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("unpinned replay of pinned intent permitted: %v", err)
	}
	// Duplicate event identity must abort the entire intent + lock transaction.
	next := testIntent(9703)
	if _, _, err := repository.CreatePinned(ctx, next, testEvent(next, 1, 9711, eventCreated), pinnedFixture(next.ID)); err == nil {
		t.Fatal("duplicate outbox event unexpectedly succeeded")
	}
	if _, err := repository.Get(ctx, next.TenantID, next.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollback left a RunIntent: %v", err)
	}
	if _, err := repository.GetCapabilityLock(ctx, next.TenantID, next.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollback left a capability lock: %v", err)
	}
}

func TestConcurrentPinnedReplaySingleOutbox(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	original := testIntent(9721)
	const workers = 8
	var wg sync.WaitGroup
	success := make(chan bool, workers)
	errs := make(chan error, workers)
	for n := 0; n < workers; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			candidate := original
			candidate.ID = testIntent(9721 + n).ID
			_, inserted, err := repository.CreatePinned(ctx, candidate,
				testEvent(candidate, 1, 9731+n, eventCreated), pinnedFixture(candidate.ID))
			if err != nil {
				errs <- err
			} else {
				success <- inserted
			}
		}(n)
	}
	wg.Wait()
	close(success)
	close(errs)
	for err := range errs {
		t.Errorf("pinned concurrent replay: %v", err)
	}
	count := 0
	for inserted := range success {
		if inserted {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("created %d pinned intents, want one", count)
	}
	if got := countOutbox(t, pool, original.ID); got != 1 {
		// The first candidate ID is not guaranteed to be original.ID, so
		// also inspect the tenant-scoped idempotency aggregate directly.
		var events int
		err := pool.QueryRow(ctx, "SELECT count(*) FROM outbox_events WHERE tenant_id=$1 AND aggregate_type='run_intent'", original.TenantID).Scan(&events)
		if err != nil || events != 1 {
			t.Fatalf("concurrent pinned Outbox count=%d (by original ID=%d), err=%v", events, got, err)
		}
	}
}

func TestPinnedRequiresMatchingRunIntentAuthority(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(9751)
	lock := pinnedFixture(intent.ID)
	lock.TenantID = "tenant-other"
	if _, _, err := repository.CreatePinned(ctx, intent, testEvent(intent, 1, 9752, eventCreated), lock); !errors.Is(err, ErrInvalidCapabilityLock) {
		t.Fatalf("mismatched tenant accepted: %v", err)
	}
	lock = pinnedFixture(intent.ID)
	lock.AgentReleaseID = "release-other"
	if _, _, err := repository.CreatePinned(ctx, intent, testEvent(intent, 1, 9753, eventCreated), lock); !errors.Is(err, ErrInvalidCapabilityLock) {
		t.Fatalf("mismatched agent release accepted: %v", err)
	}
	if got := countOutbox(t, pool, intent.ID); got != 0 {
		t.Fatalf("invalid lock emitted %d outbox events", got)
	}
}

func TestPinnedMigrationDriftRLSAndMutationGuards(t *testing.T) {
	t.Run("force rls required", func(t *testing.T) {
		_, pool := testRepository(t)
		_, err := pool.Exec(context.Background(), "ALTER TABLE run_capability_locks NO FORCE ROW LEVEL SECURITY")
		if err != nil {
			t.Fatal(err)
		}
		if err := Migrate(context.Background(), pool); !errors.Is(err, ErrSchemaDrift) {
			t.Fatalf("RLS drift passed: %v", err)
		}
	})
	t.Run("immutable lock", func(t *testing.T) {
		repository, pool := testRepository(t)
		ctx := context.Background()
		intent := testIntent(9761)
		_, _, err := repository.CreatePinned(ctx, intent, testEvent(intent, 1, 9762, eventCreated), pinnedFixture(intent.ID))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "UPDATE run_capability_locks SET workspace_id='forged' WHERE run_intent_id=$1::uuid", intent.ID); err == nil {
			t.Fatal("DAS lock mutated")
		}
		if _, err := pool.Exec(ctx, "DELETE FROM run_capability_locks WHERE run_intent_id=$1::uuid", intent.ID); err == nil {
			t.Fatal("DAS lock deleted")
		}
	})
}

func TestPinnedRestrictedRoleTenantIsolation(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(9771)
	if _, _, err := repository.CreatePinned(ctx, intent, testEvent(intent, 1, 9772, eventCreated), pinnedFixture(intent.ID)); err != nil {
		t.Fatalf("create pinned fixture: %v", err)
	}
	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := fmt.Sprintf("caplock_reader_%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatalf("create restricted role: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP OWNED BY "+role)
		_, _ = pool.Exec(context.Background(), "DROP ROLE "+role)
	})
	if _, err := pool.Exec(ctx, "GRANT USAGE ON SCHEMA "+schema+" TO "+role); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "GRANT SELECT ON "+schema+".run_capability_locks TO "+role); err != nil {
		t.Fatal(err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", intent.TenantID); err != nil {
		t.Fatal(err)
	}
	var got int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM run_capability_locks").Scan(&got); err != nil || got != 1 {
		t.Fatalf("restricted tenant cannot read own lock: count=%d err=%v", got, err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id','tenant-other',true)"); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM run_capability_locks").Scan(&got); err != nil || got != 0 {
		t.Fatalf("cross-tenant lock was visible: count=%d err=%v", got, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}
