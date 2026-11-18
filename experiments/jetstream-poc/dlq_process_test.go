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

	"github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const killedAfterDLQPubAck = "JETSTREAM_DLQ_CONFIRMED_JOURNALED_BEFORE_SOURCE_ACK"

type killDLQSourceACK struct{ jetstream.Msg }

func (m killDLQSourceACK) DoubleAck(context.Context) error {
	_, _ = fmt.Fprintln(os.Stdout, killedAfterDLQPubAck)
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

// This helper runs in an independent process with live JetStream/PG handles.
// The killing callback is reached ONLY after the DLQ has a real retained
// record and the PG disposition journal's confirmed state is durable.
func TestDLQPostPubAckSIGKILLChild(t *testing.T) {
	if os.Getenv("ACP_JS_DLQ_CHILD") != "1" {
		return
	}
	schema := os.Getenv("ACP_JS_DLQ_SCHEMA")
	if !strings.HasPrefix(schema, "test_jetstream_") {
		t.Fatal("missing isolated PG schema")
	}
	var cfg Config
	if err := json.Unmarshal([]byte(os.Getenv("ACP_JS_DLQ_CONFIG")), &cfg); err != nil {
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
	err = HandleMessage(ctx, postgres.New(pool), js, killDLQSourceACK{msg}, cfg, NewDispositionJournal(pool))
	t.Fatalf("did not die between DLQ PubAck and source ACK: %v", err)
}

func TestRealJetStreamCrashAfterConfirmedDLQBeforeSourceACK(t *testing.T) {
	repository, pool := pocRepository(t)
	js, consumer, dlq, cfg := pocNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	journal := NewDispositionJournal(pool)
	original := pocEvent(8611, 1)
	publishEvent(t, ctx, js, cfg.SourceSubject, original)
	if err := HandleMessage(ctx, repository, js, nextMessage(t, consumer), cfg, journal); err != nil {
		t.Fatal(err)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, cfg.ConsumerName, allowPOCProjection{})
	if err != nil || !applied.Applied {
		t.Fatalf("original not applied: %+v err=%v", applied, err)
	}
	changed := original
	changed.Payload = []byte(`{"version":8612}`)
	publishEvent(t, ctx, js, cfg.SourceSubject, changed)
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestDLQPostPubAckSIGKILLChild$")
	child.Env = append(os.Environ(), "ACP_JS_DLQ_CHILD=1",
		"ACP_JS_DLQ_SCHEMA="+pool.Config().ConnConfig.RuntimeParams["search_path"],
		"ACP_JS_DLQ_CONFIG="+string(cfgJSON))
	output, err := child.CombinedOutput()
	var killed *exec.ExitError
	if !errors.As(err, &killed) || killed.ExitCode() != -1 || !strings.Contains(string(output), killedAfterDLQPubAck) {
		t.Fatalf("child did not die after confirmed DLQ: err=%v output=%s", err, output)
	}
	var recorded, archived int
	var published bool
	if err := pool.QueryRow(ctx, "SELECT count(*), bool_and(published) FROM poc_dlq_dispositions").Scan(&recorded, &published); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM inbox_event_conflicts").Scan(&archived); err != nil {
		t.Fatal(err)
	}
	info, err := dlq.Info(ctx)
	if err != nil || info.State.Msgs != 1 || recorded != 1 || !published || archived != 1 {
		t.Fatalf("DLQ not durable before receiver crash: %+v journal=%d confirmed=%v archive=%d err=%v",
			info, recorded, published, archived, err)
	}
	// Explicitly outlive the one-second broker MsgID deduplication window.
	time.Sleep(1600 * time.Millisecond)
	replay := nextMessage(t, consumer)
	meta, err := replay.Metadata()
	if err != nil || meta.NumDelivered < 2 {
		t.Fatalf("no actual broker redelivery after kill: %+v err=%v", meta, err)
	}
	if err := HandleMessage(ctx, repository, js, replay, cfg, journal); err != nil {
		t.Fatalf("reconcile immutable journal/broker record then ACK: %v", err)
	}
	info, err = dlq.Info(ctx)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("duplicate DLQ after actual SIGKILL / expired MsgID window: %+v err=%v", info, err)
	}
}
