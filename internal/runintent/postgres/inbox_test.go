package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type testInboxApplier struct {
	fail bool
}

func (a *testInboxApplier) Supports(event InboxEvent) bool {
	return event.SchemaVersion == 1 && event.Type == "agent.test.changed"
}

func (a *testInboxApplier) Apply(ctx context.Context, tx pgx.Tx, event InboxEvent) error {
	if a.fail {
		return errors.New("projection temporarily unavailable")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO inbox_test_projection (
			consumer_name,tenant_id,aggregate_id,aggregate_version,event_id
		) VALUES ('test-consumer',$1,$2,$3,$4::uuid)
	`, event.TenantID, event.AggregateID, int64(event.AggregateVersion), event.ID)
	return err
}

func testInboxEvent(tenantID, aggregateID string, version uint64, eventID int) Event {
	return Event{
		ID:               fmt.Sprintf("00000000-0000-4000-8000-%012d", eventID),
		Producer:         "test-producer",
		Type:             "agent.test.changed",
		SchemaVersion:    1,
		TenantID:         tenantID,
		AggregateType:    "agent",
		AggregateID:      aggregateID,
		AggregateVersion: version,
		OccurredAt:       time.Now().UTC(),
		CorrelationID:    "test-correlation",
		Payload:          json.RawMessage(fmt.Sprintf("{\"version\":%d}", version)),
	}
}

func setupInboxProjection(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE inbox_test_projection (
			consumer_name text NOT NULL,
			tenant_id text NOT NULL,
			aggregate_id text NOT NULL,
			aggregate_version bigint NOT NULL,
			event_id uuid NOT NULL,
			PRIMARY KEY (consumer_name,tenant_id,aggregate_id,aggregate_version)
		)
	`)
	if err != nil {
		t.Fatalf("create Inbox projection fixture: %v", err)
	}
}

func TestReceiveInboxEventIsIdempotentAndQuarantinesIDConflict(t *testing.T) {
	repository, pool := testRepository(t)
	event := testInboxEvent("tenant-a", "agent-1", 1, 701)

	first, err := repository.ReceiveInboxEvent(context.Background(), "test-consumer", event)
	if err != nil || !first.Inserted || first.Duplicate {
		t.Fatalf("first receive: result=%+v err=%v", first, err)
	}
	duplicate, err := repository.ReceiveInboxEvent(context.Background(), "test-consumer", event)
	if err != nil || !duplicate.Duplicate || duplicate.Conflict {
		t.Fatalf("exact redelivery: result=%+v err=%v", duplicate, err)
	}

	conflict := event
	conflict.Payload = json.RawMessage("{\"version\":999}")
	conflicted, err := repository.ReceiveInboxEvent(context.Background(), "test-consumer", conflict)
	if err != nil || !conflicted.Conflict || !conflicted.Quarantined {
		t.Fatalf("event ID conflict: result=%+v err=%v", conflicted, err)
	}

	var eventCount int
	var state, errorCode string
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*), min(state), min(error_code)
		FROM inbox_events WHERE consumer_name = 'test-consumer'
	`).Scan(&eventCount, &state, &errorCode); err != nil {
		t.Fatalf("inspect Inbox deduplication: %v", err)
	}
	if eventCount != 1 || state != "QUARANTINED" || errorCode != "EVENT_ID_CONFLICT" {
		t.Fatalf("unexpected deduplication state: count=%d state=%q error=%q", eventCount, state, errorCode)
	}
}

func TestInboxAggregateClaimsAreTenantScopedAndConflictsAreQuarantined(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()

	first, err := repository.ReceiveInboxEvent(ctx, "test-consumer", testInboxEvent("tenant-a", "shared-agent", 1, 711))
	if err != nil || !first.Inserted {
		t.Fatalf("tenant A event: result=%+v err=%v", first, err)
	}
	secondTenant, err := repository.ReceiveInboxEvent(ctx, "test-consumer", testInboxEvent("tenant-b", "shared-agent", 1, 712))
	if err != nil || !secondTenant.Inserted || secondTenant.Quarantined {
		t.Fatalf("tenant B event with same aggregate identity: result=%+v err=%v", secondTenant, err)
	}
	conflict, err := repository.ReceiveInboxEvent(ctx, "test-consumer", testInboxEvent("tenant-a", "shared-agent", 1, 713))
	if err != nil || !conflict.Inserted || !conflict.Quarantined {
		t.Fatalf("same-tenant aggregate version conflict: result=%+v err=%v", conflict, err)
	}

	var claims, quarantined int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM inbox_aggregate_claims WHERE consumer_name = 'test-consumer'").Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM inbox_events WHERE consumer_name = 'test-consumer' AND state = 'QUARANTINED'").Scan(&quarantined); err != nil {
		t.Fatal(err)
	}
	if claims != 2 || quarantined != 1 {
		t.Fatalf("tenant-scoped claims: claims=%d quarantined=%d", claims, quarantined)
	}
}

func TestInboxDefersVersionGapThenAppliesEventsInOrder(t *testing.T) {
	repository, pool := testRepository(t)
	setupInboxProjection(t, pool)
	ctx := context.Background()
	applier := &testInboxApplier{}

	if _, err := repository.ReceiveInboxEvent(ctx, "test-consumer", testInboxEvent("tenant-a", "agent-2", 2, 722)); err != nil {
		t.Fatalf("receive version 2 first: %v", err)
	}
	gap, err := repository.ApplyInboxBatch(ctx, "test-consumer", applier, 10)
	if err != nil || gap.Processed != 0 || gap.DeferredGaps != 1 {
		t.Fatalf("missing version 1 should remain deferred: result=%+v err=%v", gap, err)
	}

	if _, err := repository.ReceiveInboxEvent(ctx, "test-consumer", testInboxEvent("tenant-a", "agent-2", 1, 721)); err != nil {
		t.Fatalf("receive missing version 1: %v", err)
	}
	applied, err := repository.ApplyInboxBatch(ctx, "test-consumer", applier, 10)
	if err != nil || applied.Processed != 2 || applied.Applied != 2 || applied.DeferredGaps != 0 {
		t.Fatalf("contiguous events should apply in order: result=%+v err=%v", applied, err)
	}

	var cursor, projectionCount, maximumVersion int
	if err := pool.QueryRow(ctx, `
		SELECT last_applied_version FROM inbox_cursors
		WHERE consumer_name='test-consumer' AND tenant_id='tenant-a'
			AND aggregate_type='agent' AND aggregate_id='agent-2'
	`).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*), max(aggregate_version) FROM inbox_test_projection
		WHERE tenant_id='tenant-a' AND aggregate_id='agent-2'
	`).Scan(&projectionCount, &maximumVersion); err != nil {
		t.Fatal(err)
	}
	if cursor != 2 || projectionCount != 2 || maximumVersion != 2 {
		t.Fatalf("unexpected ordered projection: cursor=%d count=%d maxVersion=%d", cursor, projectionCount, maximumVersion)
	}
}

func TestUnsupportedInboxSchemaQuarantinesAndBlocksLaterVersions(t *testing.T) {
	repository, pool := testRepository(t)
	setupInboxProjection(t, pool)
	ctx := context.Background()
	unsupported := testInboxEvent("tenant-a", "agent-3", 1, 731)
	unsupported.SchemaVersion = 2
	if _, err := repository.ReceiveInboxEvent(ctx, "test-consumer", unsupported); err != nil {
		t.Fatalf("receive unknown schema: %v", err)
	}

	result, err := repository.ApplyInboxBatch(ctx, "test-consumer", &testInboxApplier{}, 10)
	if err != nil || result.Quarantined != 1 || result.Applied != 0 {
		t.Fatalf("unknown schema should be quarantined: result=%+v err=%v", result, err)
	}
	if _, err := repository.ReceiveInboxEvent(ctx, "test-consumer", testInboxEvent("tenant-a", "agent-3", 2, 732)); err != nil {
		t.Fatalf("receive later aggregate version: %v", err)
	}

	deferred, err := repository.ApplyInboxBatch(ctx, "test-consumer", &testInboxApplier{}, 10)
	if err != nil || deferred.Applied != 0 || deferred.DeferredGaps != 1 {
		t.Fatalf("later version must remain blocked behind quarantine: result=%+v err=%v", deferred, err)
	}

	var state, reason string
	if err := pool.QueryRow(ctx, `
		SELECT state,error_code FROM inbox_events
		WHERE consumer_name='test-consumer' AND event_id=$1::uuid
	`, unsupported.ID).Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	if state != "QUARANTINED" || reason != "UNSUPPORTED_EVENT_SCHEMA" {
		t.Fatalf("unexpected unsupported event state: state=%q reason=%q", state, reason)
	}
}

func TestInboxProjectionAndCursorRollbackTogetherOnApplyError(t *testing.T) {
	repository, pool := testRepository(t)
	setupInboxProjection(t, pool)
	ctx := context.Background()
	event := testInboxEvent("tenant-a", "agent-4", 1, 741)
	if _, err := repository.ReceiveInboxEvent(ctx, "test-consumer", event); err != nil {
		t.Fatalf("receive event: %v", err)
	}

	applier := &testInboxApplier{fail: true}
	if _, err := repository.ApplyInboxBatch(ctx, "test-consumer", applier, 10); err == nil {
		t.Fatal("projection failure unexpectedly committed")
	}
	var projections, cursor int
	var state string
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM inbox_test_projection").Scan(&projections); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT last_applied_version FROM inbox_cursors
		WHERE consumer_name='test-consumer' AND tenant_id='tenant-a'
			AND aggregate_type='agent' AND aggregate_id='agent-4'
	`).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT state FROM inbox_events WHERE consumer_name='test-consumer' AND event_id=$1::uuid
	`, event.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if projections != 0 || cursor != 0 || state != "RECEIVED" {
		t.Fatalf("failed transaction leaked partial state: projections=%d cursor=%d eventState=%q", projections, cursor, state)
	}

	applier.fail = false
	recovered, err := repository.ApplyInboxBatch(ctx, "test-consumer", applier, 10)
	if err != nil || recovered.Applied != 1 {
		t.Fatalf("event should apply after transient failure clears: result=%+v err=%v", recovered, err)
	}
}

func TestNewInboxWorkerRejectsInvalidConfiguration(t *testing.T) {
	repository := &Repository{pool: &pgxpool.Pool{}}
	applier := &testInboxApplier{}
	_, err := NewInboxWorker(repository, applier, InboxWorkerOptions{
		ConsumerName: " ", BatchSize: 1, PollInterval: time.Second,
	})
	if err == nil {
		t.Fatal("worker accepted blank consumer identity")
	}
	_, err = NewInboxWorker(repository, applier, InboxWorkerOptions{
		ConsumerName: "test-consumer", BatchSize: maxInboxBatchSize + 1, PollInterval: time.Second,
	})
	if err == nil {
		t.Fatal("worker accepted unbounded batch size")
	}
}
