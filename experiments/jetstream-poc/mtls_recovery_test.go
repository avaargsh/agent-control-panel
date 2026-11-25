package jetstreampoc

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

var errMTLSLostConflictACK = errors.New("injected source ACK loss over mTLS")

type mtlsLostConflictACK struct{ jetstream.Msg }

func (mtlsLostConflictACK) DoubleAck(context.Context) error { return errMTLSLostConflictACK }

type mtlsRecoveryClient struct {
	jetstream.JetStream
	publishAttempts int
}

func (c *mtlsRecoveryClient) Publish(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	c.publishAttempts++
	return nil, errors.New("confirmed DLQ recovery must not republish")
}

func assertAuthenticatedInboxDLQRecovery(t *testing.T, parent context.Context, own, foreign jetstream.JetStream, tenant string, eventID int) {
	t.Helper()
	repository, pool := pocRepository(t)
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	prefix := "tenant." + tenant + "."
	cfg := Config{
		ConsumerName: "mtls-" + tenant, SourceStream: "INBOX_" + strings.ToUpper(tenant),
		SourceConsumer: "ACP_DURABLE", SourceSubject: prefix + "inbox",
		DLQStream: "DLQ_" + strings.ToUpper(tenant), DLQSubject: prefix + "dlq",
	}
	source, err := own.CreateStream(ctx, jetstream.StreamConfig{
		Name: cfg.SourceStream, Subjects: []string{cfg.SourceSubject}, Storage: jetstream.FileStorage,
	})
	if err != nil {
		t.Fatal(err)
	}
	dlq, err := own.CreateStream(ctx, jetstream.StreamConfig{
		Name: cfg.DLQStream, Subjects: []string{cfg.DLQSubject + ".*"},
		Storage: jetstream.FileStorage, Retention: jetstream.LimitsPolicy,
		Discard: jetstream.DiscardNew, DiscardNewPerSubject: true, MaxMsgsPerSubject: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := source.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable: cfg.SourceConsumer, AckPolicy: jetstream.AckExplicitPolicy,
		AckWait: time.Second, MaxDeliver: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	journal := NewDispositionJournal(pool)
	event := pocEvent(eventID, 1)
	event.TenantID = "tenant-" + tenant
	publishEvent(t, ctx, own, cfg.SourceSubject, event)
	if err := HandleMessage(ctx, repository, own, nextMessage(t, consumer), cfg, journal); err != nil {
		t.Fatalf("authenticated Inbox settlement: %v", err)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, cfg.ConsumerName, allowPOCProjection{})
	if err != nil || !applied.Applied {
		t.Fatalf("authenticated projection failed: %+v err=%v", applied, err)
	}

	conflict := event
	conflict.Payload = []byte(`{"version":2}`)
	publishEvent(t, ctx, own, cfg.SourceSubject, conflict)
	first := nextMessage(t, consumer)
	meta, err := first.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if err := HandleMessage(ctx, repository, own, mtlsLostConflictACK{first}, cfg, journal); !errors.Is(err, errMTLSLostConflictACK) {
		t.Fatalf("expected injected ACK loss after confirmed DLQ: %v", err)
	}
	retained, err := dlq.GetMsg(ctx, 1)
	if err != nil || retained == nil {
		t.Fatalf("authenticated DLQ evidence missing: %v", err)
	}
	if _, err := foreign.Stream(ctx, cfg.DLQStream); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("foreign account must not read the DLQ stream: %v", err)
	}
	if _, err := foreign.Stream(ctx, cfg.SourceStream); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("foreign account must not read the Inbox stream: %v", err)
	}

	replay := nextMessage(t, consumer)
	replayMeta, err := replay.Metadata()
	if err != nil || replayMeta.Sequence.Stream != meta.Sequence.Stream ||
		replayMeta.NumDelivered < 2 || !bytes.Equal(replay.Data(), first.Data()) {
		t.Fatalf("expected real conflict redelivery over mTLS: %+v err=%v", replayMeta, err)
	}
	recovery := &mtlsRecoveryClient{JetStream: own}
	if err := HandleMessage(ctx, repository, recovery, replay, cfg, NewDispositionJournal(pool)); err != nil {
		t.Fatalf("recover authenticated DLQ without republishing: %v", err)
	}
	after, err := dlq.GetMsg(ctx, retained.Sequence)
	if err != nil || after == nil || after.Subject != retained.Subject || !bytes.Equal(after.Data, retained.Data) {
		t.Fatalf("retained evidence changed during recovery: %v", err)
	}
	info, err := dlq.Info(ctx)
	if err != nil || info.State.Msgs != 1 || recovery.publishAttempts != 0 {
		t.Fatalf("unexpected DLQ state: %+v republish=%d err=%v", info, recovery.publishAttempts, err)
	}
	settled, err := consumer.Info(ctx)
	if err != nil || settled.AckFloor.Stream < replayMeta.Sequence.Stream || settled.NumAckPending != 0 {
		t.Fatalf("source was not settled: %+v err=%v", settled, err)
	}
	var dispositions, conflicts int
	var confirmed bool
	if err := pool.QueryRow(ctx, "SELECT count(*), bool_and(published) FROM poc_dlq_dispositions").Scan(&dispositions, &confirmed); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM inbox_event_conflicts").Scan(&conflicts); err != nil {
		t.Fatal(err)
	}
	if dispositions != 1 || conflicts != 1 || !confirmed {
		t.Fatalf("unexpected PG evidence: dispositions=%d conflicts=%d confirmed=%t", dispositions, conflicts, confirmed)
	}
}
