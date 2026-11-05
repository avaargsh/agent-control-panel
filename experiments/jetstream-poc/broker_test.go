package jetstreampoc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/inboxtransport"
	"github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const consumerID = "billing-consumer"

func pocRepository(t *testing.T) (*postgres.Repository, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "test_jetstream_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	c, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	c.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
	})
	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := NewDispositionJournal(pool).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return postgres.New(pool), pool
}

func pocNATS(t *testing.T) (jetstream.JetStream, jetstream.Consumer, jetstream.Stream, Config) {
	t.Helper()
	url := os.Getenv("NATS_POC_URL")
	if url == "" {
		t.Skip("NATS_POC_URL is not configured")
	}
	nc, err := nats.Connect(url, nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	cfg := Config{
		ConsumerName:   consumerID,
		SourceStream:   "ACP_POC_SOURCE_" + suffix,
		SourceConsumer: "ACP_POC",
		SourceSubject:  "acp.poc.source." + suffix,
		DLQStream:      "ACP_POC_DLQ_" + suffix,
		DLQSubject:     "acp.poc.dlq." + suffix,
	}
	source, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name: cfg.SourceStream, Subjects: []string{cfg.SourceSubject}, Storage: jetstream.FileStorage,
	})
	if err != nil {
		t.Fatal(err)
	}
	dlq, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name: cfg.DLQStream, Subjects: []string{cfg.DLQSubject + ".*"}, Storage: jetstream.FileStorage,
		Discard: jetstream.DiscardNew, DiscardNewPerSubject: true,
		MaxMsgsPerSubject: 1, Duplicates: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = js.DeleteStream(context.Background(), cfg.SourceStream)
		_ = js.DeleteStream(context.Background(), cfg.DLQStream)
	})
	consumer, err := source.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable: cfg.SourceConsumer, AckPolicy: jetstream.AckExplicitPolicy,
		AckWait: 650 * time.Millisecond, MaxDeliver: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	return js, consumer, dlq, cfg
}

func pocEvent(id int, value int) postgres.Event {
	return postgres.Event{
		ID:       fmt.Sprintf("00000000-0000-4000-8000-%012d", id),
		Producer: "poc-producer", Type: "agent.test.changed",
		SchemaVersion: 1, TenantID: "tenant-a", AggregateType: "agent",
		AggregateID: "jetstream-agent", AggregateVersion: 1,
		OccurredAt: time.Now().UTC(), CorrelationID: "broker-poc",
		Payload: json.RawMessage(fmt.Sprintf("{\"version\":%d}", value)),
	}
}

func publishEvent(t *testing.T, ctx context.Context, js jetstream.JetStream, subject string, event postgres.Event) {
	t.Helper()
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := js.Publish(ctx, subject, raw)
	if err != nil || ack == nil || ack.Stream == "" {
		t.Fatalf("publish source event to JetStream: ack=%+v err=%v", ack, err)
	}
}

func nextMessage(t *testing.T, consumer jetstream.Consumer) jetstream.Msg {
	t.Helper()
	m, err := consumer.Next(jetstream.FetchMaxWait(6 * time.Second))
	if err != nil || m == nil {
		t.Fatalf("fetch real durable broker delivery: %v", err)
	}
	return m
}

type ackBlackhole struct {
	*Delivery
	err error
}

func (f ackBlackhole) Ack(context.Context) error { return f.err }

type allowPOCProjection struct{}

func (allowPOCProjection) Supports(postgres.InboxEvent) bool                        { return true }
func (allowPOCProjection) Apply(context.Context, pgx.Tx, postgres.InboxEvent) error { return nil }

func TestJetStreamRealBrokerAckLossConflictAndDLQFailure(t *testing.T) {
	repository, pool := pocRepository(t)
	js, consumer, dlq, cfg := pocNATS(t)
	journal := NewDispositionJournal(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	original := pocEvent(8101, 1)
	publishEvent(t, ctx, js, cfg.SourceSubject, original)
	msg := nextMessage(t, consumer)
	delivery, err := NewDelivery(js, msg, cfg, journal)
	if err != nil {
		t.Fatal(err)
	}
	lostAck := errors.New("injected lost ACK after PostgreSQL commit")
	if err := inboxtransport.HandleDelivery(ctx, repository, ackBlackhole{Delivery: delivery, err: lostAck}, cfg.ConsumerName, original); !errors.Is(err, lostAck) {
		t.Fatalf("missing ack-loss error: %v", err)
	}
	redelivered := nextMessage(t, consumer)
	meta, err := redelivered.Metadata()
	if err != nil || meta.NumDelivered < 2 {
		t.Fatalf("JetStream did not redeliver unacked source: %+v err=%v", meta, err)
	}
	if err := HandleMessage(ctx, repository, js, redelivered, cfg, journal); err != nil {
		t.Fatalf("recover committed delivery via real JetStream ACK: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM inbox_events WHERE consumer_name=$1", cfg.ConsumerName).Scan(&count); err != nil || count != 1 {
		t.Fatalf("lost-ack replay duplicated Inbox: count=%d err=%v", count, err)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, cfg.ConsumerName, allowPOCProjection{})
	if err != nil || !applied.Applied {
		t.Fatalf("apply original before conflicting replay: %+v err=%v", applied, err)
	}

	changed := original
	changed.Payload = json.RawMessage(`{"version":999}`)
	publishEvent(t, ctx, js, cfg.SourceSubject, changed)
	if err := HandleMessage(ctx, repository, js, nextMessage(t, consumer), cfg, journal); err != nil {
		t.Fatalf("durable conflict DLQ confirmation: %v", err)
	}
	info, err := dlq.Info(ctx)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("real DLQ stream missing confirmed conflict: %+v err=%v", info, err)
	}
	raw, err := dlq.GetMsg(ctx, 1)
	if err != nil {
		t.Fatalf("inspect committed DLQ record: %v", err)
	}
	var evidence DLQEvidence
	if err := json.Unmarshal(raw.Data, &evidence); err != nil || evidence.Reason != inboxtransport.ReasonEventIDConflict || evidence.SourceStream != cfg.SourceStream {
		t.Fatalf("untrusted DLQ evidence: %+v err=%v", evidence, err)
	}
	var archived int
	var state string
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM inbox_event_conflicts WHERE consumer_name=$1", cfg.ConsumerName).Scan(&archived); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT state FROM inbox_events WHERE consumer_name=$1 AND event_id=$2::uuid", cfg.ConsumerName, original.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if archived != 1 || state != "APPLIED" {
		t.Fatalf("conflict evidence lost or original mutated: archive=%d state=%s", archived, state)
	}

	changedAgain := original
	changedAgain.Payload = json.RawMessage(`{"version":777}`)
	publishEvent(t, ctx, js, cfg.SourceSubject, changedAgain)
	failedCfg := cfg
	failedCfg.DLQStream = "ACP_WRONG_STREAM"
	if err := HandleMessage(ctx, repository, js, nextMessage(t, consumer), failedCfg, journal); err == nil {
		t.Fatal("non-durable DLQ publish was wrongly treated as terminal ACK")
	}
	if err := HandleMessage(ctx, repository, js, nextMessage(t, consumer), cfg, journal); err != nil {
		t.Fatalf("recover DLQ after failed confirmed publication: %v", err)
	}
	info, err = dlq.Info(ctx)
	if err != nil || info.State.Msgs != 2 {
		t.Fatalf("DLQ failure lost or multiplied evidence: %+v err=%v", info, err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM inbox_event_conflicts WHERE consumer_name=$1", cfg.ConsumerName).Scan(&archived); err != nil || archived != 2 {
		t.Fatalf("durable archive count after retry=%d err=%v", archived, err)
	}
}
