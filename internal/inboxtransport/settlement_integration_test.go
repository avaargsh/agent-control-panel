package inboxtransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func settlementPostgres(t *testing.T) (*postgres.Repository, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set; PostgreSQL settlement test skipped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("test_inbox_settlement_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		_ = admin.Close(context.Background())
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
		t.Fatal(err)
	}
	if err := postgres.Migrate(ctx, pool); err != nil {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
	})
	return postgres.New(pool), pool
}

type databaseObservingDelivery struct {
	pool     *pgxpool.Pool
	eventID  string
	ackCalls int
	dlqCalls int
	failAck  error
}

func (d *databaseObservingDelivery) Ack(ctx context.Context) error {
	var count int
	if err := d.pool.QueryRow(ctx,
		"SELECT count(*) FROM inbox_events WHERE consumer_name='billing-consumer' AND event_id=$1::uuid",
		d.eventID).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("broker ACK before Inbox commit: count=%d", count)
	}
	d.ackCalls++
	return d.failAck
}

func (d *databaseObservingDelivery) DeadLetter(ctx context.Context, reason string) error {
	if reason != ReasonEventIDConflict {
		return fmt.Errorf("unexpected DLQ reason: %s", reason)
	}
	var count int
	if err := d.pool.QueryRow(ctx,
		"SELECT count(*) FROM inbox_event_conflicts WHERE consumer_name='billing-consumer' AND event_id=$1::uuid",
		d.eventID).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("DLQ before durable conflict archive: count=%d", count)
	}
	d.dlqCalls++
	return nil
}

type acceptAllApplier struct{}

func (acceptAllApplier) Supports(postgres.InboxEvent) bool { return true }
func (acceptAllApplier) Apply(context.Context, pgx.Tx, postgres.InboxEvent) error {
	return nil
}

// A lost ACK occurs after the PostgreSQL transaction committed. Redelivery
// must not create a second event or evade the conflict archive if mutated.
func TestSettlementPostgresCommitLostACKAndConflictingAppliedReplay(t *testing.T) {
	repository, pool := settlementPostgres(t)
	ctx := context.Background()
	event := postgres.Event{
		ID:               "00000000-0000-4000-8000-000000000101",
		Producer:         "test-producer",
		Type:             "agent.test.changed",
		SchemaVersion:    1,
		TenantID:         "tenant-a",
		AggregateType:    "agent",
		AggregateID:      "agent-a",
		AggregateVersion: 1,
		OccurredAt:       time.Now().UTC(),
		CorrelationID:    "settlement-test",
		Payload:          json.RawMessage(`{"version":1}`),
	}
	lostAck := errors.New("simulated ACK loss")
	delivery := &databaseObservingDelivery{pool: pool, eventID: event.ID, failAck: lostAck}
	if err := HandleDelivery(ctx, repository, delivery, "billing-consumer", event); !errors.Is(err, lostAck) {
		t.Fatalf("lost broker ACK should retain retry signal: %v", err)
	}
	delivery.failAck = nil
	if err := HandleDelivery(ctx, repository, delivery, "billing-consumer", event); err != nil {
		t.Fatalf("redelivered committed Inbox event: %v", err)
	}
	var events int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM inbox_events WHERE consumer_name='billing-consumer'",
	).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 || delivery.ackCalls != 2 || delivery.dlqCalls != 0 {
		t.Fatalf("lost ACK replay not idempotent: events=%d ack=%d dlq=%d", events, delivery.ackCalls, delivery.dlqCalls)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, "billing-consumer", acceptAllApplier{})
	if err != nil || !applied.Applied {
		t.Fatalf("apply original Inbox event: result=%+v err=%v", applied, err)
	}
	conflict := event
	conflict.Payload = json.RawMessage(`{"version":999}`)
	if err := HandleDelivery(ctx, repository, delivery, "billing-consumer", conflict); err != nil {
		t.Fatalf("conflict after apply must be durably routed: %v", err)
	}
	if err := HandleDelivery(ctx, repository, delivery, "billing-consumer", conflict); err != nil {
		t.Fatalf("repeat conflict must preserve idempotent archive: %v", err)
	}
	var count int
	var state string
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM inbox_event_conflicts WHERE consumer_name='billing-consumer'",
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		"SELECT state FROM inbox_events WHERE consumer_name='billing-consumer' AND event_id=$1::uuid",
		event.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if count != 1 || state != "APPLIED" || delivery.ackCalls != 2 || delivery.dlqCalls != 2 {
		t.Fatalf("conflicting redelivery accepted or lost: archive=%d state=%q ack=%d dlq=%d",
			count, state, delivery.ackCalls, delivery.dlqCalls)
	}
}
