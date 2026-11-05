package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	"github.com/avaargsh/agent-control-panel/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testRepository(t *testing.T) (*Repository, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set; PostgreSQL integration test skipped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect PostgreSQL admin: %v", err)
	}
	schema := fmt.Sprintf("test_runintent_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		_ = admin.Close(context.Background())
		t.Fatalf("create test schema: %v", err)
	}

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
		t.Fatalf("parse PostgreSQL pool config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
		t.Fatalf("create PostgreSQL pool: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
		t.Fatalf("apply PostgreSQL migration: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("reapplying initial migration should be safe: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
	})
	return New(pool), pool
}

func testIntent(sequence int) runintent.Intent {
	return runintent.Intent{
		ID:       fmt.Sprintf("00000000-0000-4000-8000-%012d", sequence),
		TenantID: "tenant-integration", PrincipalID: "principal-integration",
		ProjectID: "project-1", AgentID: "agent-1", ReleaseID: "release-1",
		SessionID: "session-1", IdempotencyKey: fmt.Sprintf("key-%d", sequence),
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Version:       1, Status: runintent.Pending,
	}
}

func testEvent(intent runintent.Intent, version uint64, eventID int, eventType string) Event {
	return Event{
		ID:       fmt.Sprintf("00000000-0000-4000-8000-%012d", eventID),
		Producer: "agent-control-panel", Type: eventType, SchemaVersion: 1,
		TenantID: intent.TenantID, AggregateType: aggregateType,
		AggregateID: intent.ID, AggregateVersion: version,
		OccurredAt: time.Now().UTC(), CorrelationID: "correlation-integration",
		Payload: json.RawMessage([]byte("{\"run_intent_id\":\"" + intent.ID + "\"}")),
	}
}

func countOutbox(t *testing.T, pool *pgxpool.Pool, intentID string) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(),
		"SELECT count(*) FROM outbox_events WHERE aggregate_id = $1", intentID,
	).Scan(&count); err != nil {
		t.Fatalf("count Outbox events: %v", err)
	}
	return count
}

func TestCreateIsAtomicAndIdempotent(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(1)
	event := testEvent(intent, 1, 101, eventCreated)

	created, inserted, err := repository.Create(ctx, intent, event)
	if err != nil || !inserted || created.ID != intent.ID {
		t.Fatalf("create: inserted=%v intent=%+v err=%v", inserted, created, err)
	}

	replayed, inserted, err := repository.Create(ctx, intent, testEvent(intent, 1, 102, eventCreated))
	if err != nil || inserted || replayed.ID != intent.ID {
		t.Fatalf("idempotent replay: inserted=%v intent=%+v err=%v", inserted, replayed, err)
	}
	if got := countOutbox(t, pool, intent.ID); got != 1 {
		t.Fatalf("idempotent replay emitted %d Outbox events, want 1", got)
	}

	conflicting := intent
	conflicting.RequestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	_, _, err = repository.Create(ctx, conflicting, testEvent(conflicting, 1, 103, eventCreated))
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("reused key with changed request digest: got %v", err)
	}
}

func TestCompareAndSwapAndOutboxShareTransaction(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(2)
	created, inserted, err := repository.Create(ctx, intent, testEvent(intent, 1, 201, eventCreated))
	if err != nil || !inserted {
		t.Fatalf("create: inserted=%v err=%v", inserted, err)
	}

	next, err := created.ClaimDispatch(created.Version, "dispatcher-1", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatalf("claim dispatch: %v", err)
	}
	updated, err := repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, created.Version, next,
		testEvent(next, next.Version, 202, "agent.run-intent.dispatching"))
	if err != nil || updated.Status != runintent.Dispatching {
		t.Fatalf("persist transition: updated=%+v err=%v", updated, err)
	}
	if got := countOutbox(t, pool, intent.ID); got != 2 {
		t.Fatalf("Outbox count after transition = %d, want 2", got)
	}
	if _, err := repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, created.Version, next,
		testEvent(next, next.Version, 203, "agent.run-intent.dispatching")); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("stale CAS returned %v, want ErrStaleVersion", err)
	}

	rollbackIntent := testIntent(3)
	_, _, err = repository.Create(ctx, rollbackIntent, testEvent(rollbackIntent, 1, 301, eventCreated))
	if err != nil {
		t.Fatalf("create rollback fixture: %v", err)
	}
	rollbackNext, err := rollbackIntent.ClaimDispatch(1, "dispatcher-2", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatalf("claim rollback fixture: %v", err)
	}
	// Reusing an existing event UUID forces the Outbox insert to fail. The
	// enclosing transaction must also roll back the RunIntent state update.
	if _, err := repository.CompareAndSwap(ctx, rollbackIntent.TenantID, rollbackIntent.ID, 1, rollbackNext,
		testEvent(rollbackNext, rollbackNext.Version, 301, "agent.run-intent.dispatching")); err == nil {
		t.Fatal("duplicate Outbox event ID unexpectedly committed")
	}
	unchanged, err := repository.Get(ctx, rollbackIntent.TenantID, rollbackIntent.ID)
	if err != nil {
		t.Fatalf("read rollback fixture: %v", err)
	}
	if unchanged.Status != runintent.Pending || unchanged.Version != 1 || countOutbox(t, pool, rollbackIntent.ID) != 1 {
		t.Fatalf("partial transaction escaped rollback: %+v", unchanged)
	}
}

func TestConcurrentIdempotencyClaimsCreateOneRecordAndEvent(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(4)
	const workers = 12
	var wait sync.WaitGroup
	created := make(chan bool, workers)
	errs := make(chan error, workers)

	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, inserted, err := repository.Create(ctx, intent,
				testEvent(intent, 1, 400+worker, eventCreated))
			if err != nil {
				errs <- err
				return
			}
			created <- inserted
		}()
	}
	wait.Wait()
	close(created)
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Create failed: %v", err)
	}
	createdCount := 0
	for inserted := range created {
		if inserted {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("concurrent inserts created %d rows, want exactly 1", createdCount)
	}
	if got := countOutbox(t, pool, intent.ID); got != 1 {
		t.Fatalf("concurrent idempotency claim created %d Outbox events, want 1", got)
	}
}

func TestCompareAndSwapRequiresNewFenceForNewLease(t *testing.T) {
	repository, _ := testRepository(t)
	ctx := context.Background()
	intent := testIntent(5)
	created, inserted, err := repository.Create(ctx, intent, testEvent(intent, 1, 501, eventCreated))
	if err != nil || !inserted {
		t.Fatalf("create: inserted=%v err=%v", inserted, err)
	}
	now := time.Now().UTC()
	dispatching, err := created.ClaimDispatch(created.Version, "dispatcher-1", now, time.Second)
	if err != nil {
		t.Fatalf("claim dispatch: %v", err)
	}
	dispatching, err = repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, created.Version, dispatching,
		testEvent(dispatching, dispatching.Version, 502, "agent.run-intent.dispatching"))
	if err != nil {
		t.Fatalf("persist dispatch lease: %v", err)
	}
	unknown, err := dispatching.ExpireLease(dispatching.Version, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("expire dispatch lease: %v", err)
	}
	unknown, err = repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, dispatching.Version, unknown,
		testEvent(unknown, unknown.Version, 503, "agent.run-intent.unknown"))
	if err != nil {
		t.Fatalf("persist expired dispatch lease: %v", err)
	}
	reconciling, err := unknown.BeginReconciliation(unknown.Version, "reconciler-1", now.Add(3*time.Second), time.Minute)
	if err != nil {
		t.Fatalf("begin reconciliation: %v", err)
	}
	// A well-formed but stale lease token must not be persisted for a newly
	// acquired lease, even when the status and version are otherwise valid.
	reconciling.FenceToken = unknown.FenceToken
	if _, err := repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, unknown.Version, reconciling,
		testEvent(reconciling, reconciling.Version, 504, "agent.run-intent.reconciling")); !errors.Is(err, ErrFenceRegression) {
		t.Fatalf("new lease with reused fence token returned %v, want ErrFenceRegression", err)
	}
}

func TestCreateReplayRejectsChangedOwnerMetadataWithSameDigest(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	original := testIntent(5)
	created, inserted, err := repository.Create(ctx, original, testEvent(original, 1, 501, eventCreated))
	if err != nil || !inserted {
		t.Fatalf("create original: inserted=%v err=%v", inserted, err)
	}

	cases := []struct {
		name   string
		mutate func(*runintent.Intent)
	}{
		{"project", func(i *runintent.Intent) { i.ProjectID = "project-other" }},
		{"agent", func(i *runintent.Intent) { i.AgentID = "agent-other" }},
		{"release", func(i *runintent.Intent) { i.ReleaseID = "release-other" }},
		{"session", func(i *runintent.Intent) { i.SessionID = "session-other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := original
			changed.ID = fmt.Sprintf("00000000-0000-4000-8000-%012d", 600+len(tc.name))
			tc.mutate(&changed)
			_, inserted, err := repository.Create(ctx, changed,
				testEvent(changed, 1, 700+len(tc.name), eventCreated))
			if !errors.Is(err, ErrIdempotencyConflict) || inserted {
				t.Fatalf("changed %s was replayed: inserted=%v err=%v", tc.name, inserted, err)
			}
		})
	}

	// Candidate IDs are not part of the replay fingerprint: a legitimate retry
	// must return the original durable ID, not the new uncommitted candidate.
	retry := original
	retry.ID = "00000000-0000-4000-8000-000000000999"
	replayed, inserted, err := repository.Create(ctx, retry, testEvent(retry, 1, 999, eventCreated))
	if err != nil || inserted || replayed.ID != created.ID {
		t.Fatalf("same-identity retry: inserted=%v replayed=%+v err=%v", inserted, replayed, err)
	}
	if got := countOutbox(t, pool, original.ID); got != 1 {
		t.Fatalf("ownership conflicts or replay emitted %d Outbox events, want 1", got)
	}
}

// Existing databases with a recorded v1 migration must receive the new
// conflict archive through an additive v2 migration, not rewritten v1 SQL.
func TestMigrationUpgradesRecordedV1ToConflictEvidenceV2(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "DROP TABLE inbox_event_conflicts"); err != nil {
		t.Fatalf("simulate recorded v1 schema: %v", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version=2"); err != nil {
		t.Fatalf("remove simulated future version ledger: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("upgrade recorded v1 to v2: %v", err)
	}
	var installed bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM schema_migrations WHERE version=2
		) AND to_regclass('inbox_event_conflicts') IS NOT NULL
	`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Fatal("conflict-evidence v2 migration was not installed")
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("repeat conflict-evidence v2 migration: %v", err)
	}
}

func TestMigrationRejectsMissingConflictArchiveTruncateTrigger(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		DROP TRIGGER inbox_conflict_evidence_no_truncate ON inbox_event_conflicts
	`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("missing conflict archive TRUNCATE guard accepted: %v", err)
	}
}

// A matching migration checksum and familiar object names do not establish
// that the live conflict archive still has the originally reviewed protections.
func TestMigrationRejectsSameNameButChangedInboxConflictGuards(t *testing.T) {
	cases := []struct {
		name       string
		statements []string
	}{
		{
			name: "same-named trigger changed from truncate to insert",
			statements: []string{
				"DROP TRIGGER inbox_conflict_evidence_no_truncate ON inbox_event_conflicts",
				`CREATE TRIGGER inbox_conflict_evidence_no_truncate
				 BEFORE INSERT ON inbox_event_conflicts
				 FOR EACH ROW EXECUTE FUNCTION reject_inbox_conflict_evidence_mutation()`,
			},
		},
		{
			name: "same-named archive primary key no longer contains digest",
			statements: []string{
				"ALTER TABLE inbox_event_conflicts DROP CONSTRAINT inbox_event_conflicts_pkey",
				`ALTER TABLE inbox_event_conflicts ADD CONSTRAINT inbox_event_conflicts_pkey
				 PRIMARY KEY (consumer_name,event_id)`,
			},
		},
		{
			name: "trigger function body changed to no-op",
			statements: []string{
				`CREATE OR REPLACE FUNCTION reject_inbox_conflict_evidence_mutation()
				 RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NULL; END;'`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx := context.Background()
			for _, sql := range tc.statements {
				if _, err := pool.Exec(ctx, sql); err != nil {
					t.Fatalf("inject same-name catalog drift: %v", err)
				}
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("same-name altered archive guard passed: %v, want ErrSchemaDrift", err)
			}
		})
	}
}

func TestMigrationHistoryChecksumAndSchemaDrift(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	var version int64
	var name, checksum string
	if err := pool.QueryRow(ctx,
		"SELECT version, name, checksum FROM schema_migrations WHERE version=1",
	).Scan(&version, &name, &checksum); err != nil {
		t.Fatalf("read migration history: %v", err)
	}
	if version != 1 || name != "0001_run_intents_outbox_inbox.sql" || len(checksum) != 64 {
		t.Fatalf("unexpected migration record: version=%d name=%q checksum=%q", version, name, checksum)
	}
	source, err := migrations.FS.ReadFile("0001_run_intents_outbox_inbox.sql")
	if err != nil {
		t.Fatal(err)
	}
	wantChecksum := fmt.Sprintf("%x", sha256.Sum256(source))
	if checksum != wantChecksum {
		t.Fatalf("migration checksum=%s want=%s", checksum, wantChecksum)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE schema_migrations SET checksum=$1 WHERE version=1",
		strings.Repeat("0", 64),
	); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("changed migration checksum accepted: %v", err)
	}
}

func TestMigrationRejectsUnversionedExistingSchema(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "DROP TABLE schema_migrations"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrUnversionedSchema) {
		t.Fatalf("unversioned schema was silently adopted: %v", err)
	}
}

func TestMigrationDetectsMissingRelationAfterRecordedInstall(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "DROP TABLE inbox_cursors"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("incomplete recorded schema was accepted: %v", err)
	}
}

func TestMigrationDetectsMissingCriticalConstraintAfterRecordedInstall(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "ALTER TABLE run_intents DROP CONSTRAINT run_intents_state_payload_consistency"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("schema with missing state/payload ownership constraint was accepted: %v", err)
	}
}

// A checksum-valid v1 database can still have its live constraints replaced.
// Constraint name lookup alone is insufficient: table, type and key columns
// must match the original reviewed migration contract.
func TestMigrationRejectsSameNameCriticalConstraintsWithDifferentBindings(t *testing.T) {
	cases := []struct {
		name       string
		statements []string
	}{
		{
			name: "state ownership check moved to unrelated relation",
			statements: []string{
				"ALTER TABLE run_intents DROP CONSTRAINT run_intents_state_payload_consistency",
				"ALTER TABLE outbox_events ADD CONSTRAINT run_intents_state_payload_consistency CHECK (true)",
			},
		},
		{
			name: "state ownership check replaced by different constraint type",
			statements: []string{
				"ALTER TABLE run_intents DROP CONSTRAINT run_intents_state_payload_consistency",
				"ALTER TABLE run_intents ADD CONSTRAINT run_intents_state_payload_consistency UNIQUE (tenant_id,id)",
			},
		},
		{
			name: "idempotency uniqueness no longer binds operation",
			statements: []string{
				"ALTER TABLE run_intents DROP CONSTRAINT run_intents_idempotency_unique",
				"ALTER TABLE run_intents ADD CONSTRAINT run_intents_idempotency_unique UNIQUE (tenant_id,principal_id,idempotency_key)",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx := context.Background()
			for _, stmt := range tc.statements {
				if _, err := pool.Exec(ctx, stmt); err != nil {
					t.Fatalf("inject live catalog drift: %v", err)
				}
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("same-name weakened RunIntent guard accepted: %v, want ErrSchemaDrift", err)
			}
		})
	}
}

// Same-name CHECK constraints may be replaced by weakened expressions while
// preserving their table, type and catalog validity. The migration verifier
// must compare each predicate to the pinned v1 migration, not just the name.
func TestMigrationRejectsWeakenedCriticalCheckPredicates(t *testing.T) {
	cases := []struct {
		name       string
		relation   string
		constraint string
	}{
		{"RunIntent lease consistency", "run_intents", "run_intents_lease_consistency"},
		{"RunIntent state payload ownership", "run_intents", "run_intents_state_payload_consistency"},
		{"Outbox publish lease", "outbox_events", "outbox_lease_consistency"},
		{"Outbox published timestamp", "outbox_events", "outbox_published_consistency"},
		{"Inbox applied timestamp", "inbox_events", "inbox_applied_consistency"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx := context.Background()
			// The table and constraint identifiers are fixed test literals.
			if _, err := pool.Exec(ctx, "ALTER TABLE "+tc.relation+
				" DROP CONSTRAINT "+tc.constraint); err != nil {
				t.Fatalf("remove original CHECK: %v", err)
			}
			if _, err := pool.Exec(ctx, "ALTER TABLE "+tc.relation+
				" ADD CONSTRAINT "+tc.constraint+" CHECK (TRUE)"); err != nil {
				t.Fatalf("install weakened same-name CHECK: %v", err)
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("weakened CHECK accepted: %v, want ErrSchemaDrift", err)
			}
		})
	}
}

// A valid-looking receipt generated with the worker's old local time cannot
// commit once PostgreSQL considers the dispatch lease expired.
func TestCASRejectsExpiredDispatchReceiptUsingDatabaseClock(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(810)
	created, inserted, err := repository.Create(ctx, intent, testEvent(intent, 1, 8101, eventCreated))
	if err != nil || !inserted {
		t.Fatalf("create RunIntent: inserted=%v err=%v", inserted, err)
	}
	dispatching, err := created.ClaimDispatch(created.Version, "worker-old", time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dispatching, err = repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, created.Version, dispatching,
		testEvent(dispatching, dispatching.Version, 8102, "agent.run-intent.dispatching"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE run_intents SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
		intent.ID); err != nil {
		t.Fatal(err)
	}
	// An old worker has no authority to claim that its original clock is
	// still valid, even if the in-memory domain transition passes.
	accepted, err := dispatching.RecordDispatchOutcome(dispatching.Version, "worker-old",
		dispatching.FenceToken, time.Now().UTC(), runintent.DispatchOutcome{
			TenantID: intent.TenantID, RunIntentID: intent.ID,
			RequestDigest: intent.RequestDigest, Kind: runintent.DispatchAccepted,
			RunID: "runtime-run-810", WorkflowID: "agent-run/v1/runtime-run-810",
		})
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, dispatching.Version, accepted,
		testEvent(accepted, accepted.Version, 8103, "agent.run-intent.accepted"))
	if !errors.Is(err, runintent.ErrLeaseExpired) {
		t.Fatalf("post-expiry ACCEPTED CAS: %v, want ErrLeaseExpired", err)
	}
	stored, err := repository.Get(ctx, intent.TenantID, intent.ID)
	if err != nil || stored.Status != runintent.Dispatching || countOutbox(t, pool, intent.ID) != 2 {
		t.Fatalf("stale receipt mutated durable state or Outbox: stored=%+v err=%v", stored, err)
	}
}

func TestCASRejectsPrematureLeaseExpiryUsingDatabaseClock(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(811)
	created, _, err := repository.Create(ctx, intent, testEvent(intent, 1, 8111, eventCreated))
	if err != nil {
		t.Fatal(err)
	}
	claimedAt := time.Now().UTC()
	dispatching, err := created.ClaimDispatch(created.Version, "worker-811", claimedAt, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dispatching, err = repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, created.Version, dispatching,
		testEvent(dispatching, dispatching.Version, 8112, "agent.run-intent.dispatching"))
	if err != nil {
		t.Fatal(err)
	}
	expired, err := dispatching.ExpireLease(dispatching.Version, claimedAt.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, dispatching.Version, expired,
		testEvent(expired, expired.Version, 8113, "agent.run-intent.unknown"))
	if !errors.Is(err, runintent.ErrLeaseActive) {
		t.Fatalf("future-dated worker prematurely expired active lease: %v, want ErrLeaseActive", err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE run_intents SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
		intent.ID); err != nil {
		t.Fatal(err)
	}
	updated, err := repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, dispatching.Version, expired,
		testEvent(expired, expired.Version, 8114, "agent.run-intent.unknown"))
	if err != nil || updated.Status != runintent.Unknown {
		t.Fatalf("genuinely expired lease should be recoverable: updated=%+v err=%v", updated, err)
	}
}

func TestCASRejectsForgedFenceIncreaseOnAcceptedReceipt(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(812)
	created, _, err := repository.Create(ctx, intent, testEvent(intent, 1, 8121, eventCreated))
	if err != nil {
		t.Fatal(err)
	}
	dispatching, err := created.ClaimDispatch(created.Version, "worker-812", time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dispatching, err = repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, created.Version, dispatching,
		testEvent(dispatching, dispatching.Version, 8122, "agent.run-intent.dispatching"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := dispatching.RecordDispatchOutcome(dispatching.Version, "worker-812",
		dispatching.FenceToken, time.Now().UTC(), runintent.DispatchOutcome{
			TenantID: intent.TenantID, RunIntentID: intent.ID,
			RequestDigest: intent.RequestDigest, Kind: runintent.DispatchAccepted,
			RunID: "runtime-run-812", WorkflowID: "agent-run/v1/runtime-run-812",
		})
	if err != nil {
		t.Fatal(err)
	}
	accepted.FenceToken++ // only lease acquisition/expiry may advance the fence
	_, err = repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, dispatching.Version, accepted,
		testEvent(accepted, accepted.Version, 8123, "agent.run-intent.accepted"))
	if !errors.Is(err, ErrFenceRegression) {
		t.Fatalf("forged accepted-receipt fence increment: %v, want ErrFenceRegression", err)
	}
	if got := countOutbox(t, pool, intent.ID); got != 2 {
		t.Fatalf("forged receipt appended an Outbox event: %d", got)
	}
}

func TestCASRejectsExpiredReconciliationResultUsingDatabaseClock(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(813)
	created, _, err := repository.Create(ctx, intent, testEvent(intent, 1, 8131, eventCreated))
	if err != nil {
		t.Fatal(err)
	}
	dispatching, err := created.ClaimDispatch(created.Version, "worker-813", time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dispatching, err = repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, created.Version, dispatching,
		testEvent(dispatching, dispatching.Version, 8132, "agent.run-intent.dispatching"))
	if err != nil {
		t.Fatal(err)
	}
	ambiguous, err := dispatching.RecordDispatchOutcome(dispatching.Version, "worker-813",
		dispatching.FenceToken, time.Now().UTC(), runintent.DispatchOutcome{
			TenantID: intent.TenantID, RunIntentID: intent.ID,
			RequestDigest: intent.RequestDigest, Kind: runintent.DispatchAmbiguous,
		})
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, dispatching.Version, ambiguous,
		testEvent(ambiguous, ambiguous.Version, 8133, "agent.run-intent.unknown"))
	if err != nil {
		t.Fatal(err)
	}
	reconciling, err := unknown.BeginReconciliation(unknown.Version, "reconciler-813", time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reconciling, err = repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, unknown.Version, reconciling,
		testEvent(reconciling, reconciling.Version, 8134, "agent.run-intent.reconciling"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE run_intents SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
		intent.ID); err != nil {
		t.Fatal(err)
	}
	retry, err := reconciling.ApplyReconciliationResult(reconciling.Version, "reconciler-813",
		reconciling.FenceToken, time.Now().UTC(), runintent.ReconciliationResult{
			TenantID: intent.TenantID, RunIntentID: intent.ID,
			RequestDigest: intent.RequestDigest, Kind: runintent.RuntimeNotFoundFinal,
		})
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.CompareAndSwap(ctx, intent.TenantID, intent.ID, reconciling.Version, retry,
		testEvent(retry, retry.Version, 8135, "agent.run-intent.pending"))
	if !errors.Is(err, runintent.ErrLeaseExpired) {
		t.Fatalf("expired reconciler could authorize another StartRun: %v, want ErrLeaseExpired", err)
	}
	stored, err := repository.Get(ctx, intent.TenantID, intent.ID)
	if err != nil || stored.Status != runintent.Reconciling || countOutbox(t, pool, intent.ID) != 4 {
		t.Fatalf("stale reconciliation result mutated durable state: stored=%+v err=%v", stored, err)
	}
}
