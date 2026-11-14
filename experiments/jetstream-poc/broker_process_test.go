package jetstreampoc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/inboxtransport"
	"github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const killedAtBrokerAck = "JETSTREAM_PG_COMMITTED_BEFORE_DOUBLE_ACK"

type killBeforeSourceAck struct{}

func (killBeforeSourceAck) Ack(context.Context) error {
	_, _ = fmt.Fprintln(os.Stdout, killedAtBrokerAck)
	_ = os.Stdout.Sync()
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	if err := self.Kill(); err != nil {
		return err
	}
	return errors.New("receiver survived SIGKILL")
}
func (killBeforeSourceAck) DeadLetter(context.Context, string) error {
	return errors.New("unexpected DLQ during ACK-loss crash scenario")
}

// Test helper is a separate OS process connected to the same PostgreSQL
// schema and *real* JetStream durable consumer as the controlling test.
func TestRealJetStreamSIGKILLChild(t *testing.T) {
	if os.Getenv("ACP_JS_POC_CHILD") != "1" {
		return
	}
	schema := os.Getenv("ACP_JS_POC_SCHEMA")
	if !strings.HasPrefix(schema, "test_jetstream_") {
		t.Fatal("missing isolated database schema")
	}
	var cfg Config
	if err := json.Unmarshal([]byte(os.Getenv("ACP_JS_POC_CONFIG")), &cfg); err != nil {
		t.Fatal(err)
	}
	pc, err := pgxpool.ParseConfig(os.Getenv("PGTEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.RuntimeParams["search_path"] = schema
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	nc, err := nats.Connect(os.Getenv("NATS_POC_URL"), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := js.Stream(ctx, cfg.SourceStream)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := stream.Consumer(ctx, cfg.SourceConsumer)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := consumer.Next(jetstream.FetchMaxWait(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var event postgres.Event
	if err := json.Unmarshal(msg.Data(), &event); err != nil {
		t.Fatal(err)
	}
	// The real broker delivery is not acknowledged here. The callback
	// kills this process only after ReceiveInboxEvent has committed.
	if err := inboxtransport.HandleDelivery(ctx, postgres.New(pool), killBeforeSourceAck{}, cfg.ConsumerName, event); err != nil {
		t.Fatalf("durable receive failed before crash: %v", err)
	}
	t.Fatal("receiver returned without SIGKILL")
}

func TestRealJetStreamCrashAfterPGCommitBeforeBrokerACK(t *testing.T) {
	repository, pool := pocRepository(t)
	js, consumer, _, cfg := pocNATS(t)
	journal := NewDispositionJournal(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	event := pocEvent(8191, 1)
	publishEvent(t, ctx, js, cfg.SourceSubject, event)

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestRealJetStreamSIGKILLChild$")
	child.Env = append(os.Environ(), "ACP_JS_POC_CHILD=1",
		"ACP_JS_POC_SCHEMA="+pool.Config().ConnConfig.RuntimeParams["search_path"],
		"ACP_JS_POC_CONFIG="+string(encoded))
	output, err := child.CombinedOutput()
	var killed *exec.ExitError
	if !errors.As(err, &killed) || killed.ExitCode() != -1 || !strings.Contains(string(output), killedAtBrokerAck) {
		t.Fatalf("real receiver was not SIGKILLed after commit: err=%v output=%s", err, output)
	}

	var count int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM inbox_events WHERE consumer_name=$1 AND event_id=$2::uuid",
		cfg.ConsumerName, event.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("committed Inbox record missing after SIGKILL: %d err=%v", count, err)
	}
	// This message was never ACKed by the child; the actual JetStream server
	// must now redeliver to the parent process, not merely invoke a fake Ack.
	msg := nextMessage(t, consumer)
	meta, err := msg.Metadata()
	if err != nil || meta.NumDelivered < 2 {
		t.Fatalf("no actual broker redelivery after receiver SIGKILL: %+v err=%v", meta, err)
	}
	if err := HandleMessage(ctx, repository, js, msg, cfg, journal); err != nil {
		t.Fatalf("restart did not safely double-ACK source: %v", err)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, cfg.ConsumerName, allowPOCProjection{})
	if err != nil || !applied.Applied {
		t.Fatalf("restart did not apply one contiguous event: %+v err=%v", applied, err)
	}
	again, err := repository.ApplyNextInboxEvent(ctx, cfg.ConsumerName, allowPOCProjection{})
	if err != nil || again.Found {
		t.Fatalf("restart duplicated projection: %+v err=%v", again, err)
	}
	var version int
	if err := pool.QueryRow(ctx,
		"SELECT last_applied_version FROM inbox_cursors WHERE consumer_name=$1 AND tenant_id=$2 AND aggregate_id=$3",
		cfg.ConsumerName, event.TenantID, event.AggregateID).Scan(&version); err != nil || version != 1 {
		t.Fatalf("cursor invalid after durable broker replay: %d err=%v", version, err)
	}
}
