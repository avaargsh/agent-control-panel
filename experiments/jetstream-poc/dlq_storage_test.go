package jetstreampoc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// A broker PubAck from volatile storage must not authorize terminal source
// ACK. Check the live stream configuration before recording a publish claim.
func TestRealJetStreamRejectsVolatileDLQBeforeClaimAndACK(t *testing.T) {
	repository, pool := pocRepository(t)
	js, consumer, durable, cfg := pocNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	journal := NewDispositionJournal(pool)

	original := pocEvent(8973, 1)
	publishEvent(t, ctx, js, cfg.SourceSubject, original)
	if err := HandleMessage(ctx, repository, js, nextMessage(t, consumer), cfg, journal); err != nil {
		t.Fatal(err)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, cfg.ConsumerName, allowPOCProjection{})
	if err != nil || !applied.Applied {
		t.Fatalf("original not applied: %+v err=%v", applied, err)
	}

	volatileCfg := cfg
	volatileCfg.DLQStream += "_VOLATILE"
	volatileCfg.DLQSubject += ".volatile"
	volatile, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name: volatileCfg.DLQStream, Subjects: []string{volatileCfg.DLQSubject + ".*"},
		Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy,
		Discard: jetstream.DiscardNew, DiscardNewPerSubject: true,
		MaxMsgsPerSubject: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = js.DeleteStream(cleanup, volatileCfg.DLQStream)
	})
	changed := original
	changed.Payload = []byte(`{"version":8974}`)
	publishEvent(t, ctx, js, cfg.SourceSubject, changed)
	first := nextMessage(t, consumer)
	firstMeta, err := first.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if err := HandleMessage(ctx, repository, js, first, volatileCfg, journal); !errors.Is(err, ErrUntrustedBrokerDelivery) {
		t.Fatalf("volatile DLQ must be rejected before claim and ACK: %v", err)
	}
	info, err := volatile.Info(ctx)
	if err != nil || info.State.Msgs != 0 {
		t.Fatalf("volatile DLQ must remain empty: %+v err=%v", info, err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM poc_dlq_dispositions").Scan(&count); err != nil || count != 0 {
		t.Fatalf("volatile DLQ must not acquire a durable claim: count=%d err=%v", count, err)
	}

	replay := nextMessage(t, consumer)
	meta, err := replay.Metadata()
	if err != nil || meta.Sequence.Stream != firstMeta.Sequence.Stream || meta.NumDelivered < 2 {
		t.Fatalf("expected unacknowledged source redelivery: %+v err=%v", meta, err)
	}
	if err := HandleMessage(ctx, repository, js, replay, cfg, journal); err != nil {
		t.Fatalf("settle using durable file-backed DLQ: %v", err)
	}
	info, err = durable.Info(ctx)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("expected one durable DLQ record: %+v err=%v", info, err)
	}
	var confirmed bool
	if err := pool.QueryRow(ctx, "SELECT count(*), bool_and(published) FROM poc_dlq_dispositions").Scan(&count, &confirmed); err != nil || count != 1 || !confirmed {
		t.Fatalf("expected one confirmed disposition: count=%d confirmed=%t err=%v", count, confirmed, err)
	}
}
