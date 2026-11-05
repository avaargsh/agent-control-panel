package jetstreampoc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/inboxtransport"
	"github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/nats-io/nats.go/jetstream"
)

type lostDLQSourceAck struct{ jetstream.Msg }

func (m lostDLQSourceAck) DoubleAck(context.Context) error {
	return errors.New("injected source ACK loss after confirmed DLQ publication")
}

// The broker's rolling Nats-Msg-Id window MUST NOT be our lifetime
// deduplication boundary. The source message is actually redelivered by NATS.
func TestDurableDispositionJournalPreventsDLQReplayBeyondDedupWindow(t *testing.T) {
	repository, pool := pocRepository(t)
	js, consumer, dlq, cfg := pocNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	journal := NewDispositionJournal(pool)
	if err := journal.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	original := pocEvent(8401, 1)
	publishEvent(t, ctx, js, cfg.SourceSubject, original)
	if err := HandleMessage(ctx, repository, js, nextMessage(t, consumer), cfg, journal); err != nil {
		t.Fatalf("apply initial source intake: %v", err)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, cfg.ConsumerName, allowPOCProjection{})
	if err != nil || !applied.Applied {
		t.Fatalf("original not APPLIED: %+v err=%v", applied, err)
	}
	conflict := original
	conflict.Payload = []byte(`{"version":9001}`)
	publishEvent(t, ctx, js, cfg.SourceSubject, conflict)
	first := nextMessage(t, consumer)
	if err := HandleMessage(ctx, repository, js, lostDLQSourceAck{first}, cfg, journal); err == nil {
		t.Fatal("source ACK loss wrongly treated as completed")
	}
	info, err := dlq.Info(ctx)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("DLQ evidence not committed before ACK-loss: %+v err=%v", info, err)
	}
	// Force rolling MsgID dedup window to expire before the source redelivery.
	time.Sleep(1600 * time.Millisecond)
	redelivery := nextMessage(t, consumer)
	meta, err := redelivery.Metadata()
	if err != nil || meta.NumDelivered < 2 {
		t.Fatalf("no actual JetStream redelivery: %+v err=%v", meta, err)
	}
	if err := HandleMessage(ctx, repository, js, redelivery, cfg, journal); err != nil {
		t.Fatalf("reconcile published disposition and ACK source: %v", err)
	}
	info, err = dlq.Info(ctx)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("duplicate DLQ record after dedup window: %+v err=%v", info, err)
	}
	var archived, dispositions int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM inbox_event_conflicts").Scan(&archived); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM poc_dlq_dispositions WHERE source_stream=$1 AND source_consumer=$2", cfg.SourceStream, cfg.SourceConsumer).Scan(&dispositions); err != nil {
		t.Fatal(err)
	}
	if archived != 1 || dispositions != 1 {
		t.Fatalf("non-idempotent DLQ evidence: archived=%d dispositions=%d", archived, dispositions)
	}
}

// A PG receipt must never be enough to ACK if the DLQ record has been
// removed/expired; recovery requires independently verified broker evidence.
func TestDurableDispositionJournalFailsClosedWhenDLQRecordIsMissing(t *testing.T) {
	repository, pool := pocRepository(t)
	js, consumer, dlq, cfg := pocNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	journal := NewDispositionJournal(pool)
	if err := journal.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	event := pocEvent(8402, 1)
	publishEvent(t, ctx, js, cfg.SourceSubject, event)
	if err := HandleMessage(ctx, repository, js, nextMessage(t, consumer), cfg, journal); err != nil {
		t.Fatal(err)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, cfg.ConsumerName, allowPOCProjection{})
	if err != nil || !applied.Applied {
		t.Fatalf("original not APPLIED: %+v err=%v", applied, err)
	}
	changed := event
	changed.Payload = []byte(`{"version":9002}`)
	publishEvent(t, ctx, js, cfg.SourceSubject, changed)
	if err := HandleMessage(ctx, repository, js, lostDLQSourceAck{nextMessage(t, consumer)}, cfg, journal); err == nil {
		t.Fatal("injected source ACK failure not observed")
	}
	raw, err := dlq.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := dlq.DeleteMsg(ctx, raw.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := HandleMessage(ctx, repository, js, nextMessage(t, consumer), cfg, journal); !errors.Is(err, ErrDLQEvidenceMissing) {
		t.Fatalf("missing DLQ evidence incorrectly ACKed or republished: %v", err)
	}
	info, err := dlq.Info(ctx)
	if err != nil || info.State.Msgs != 0 {
		t.Fatalf("missing DLQ evidence silently recreated: %+v err=%v", info, err)
	}
}

// The check on an invalid POC journal is not proof of a real broker
// deployment IAM policy; it ensures no unjournaled DLQ side effects.
func TestUnconfiguredDispositionJournalCannotSettleConflict(t *testing.T) {
	if _, err := ValidateDispositionJournal(nil); !errors.Is(err, ErrDispositionJournalRequired) {
		t.Fatalf("missing durable journal permitted: %v", err)
	}
	_ = inboxtransport.ReasonEventIDConflict
	_ = postgres.InboxReceiveResult{}
}
