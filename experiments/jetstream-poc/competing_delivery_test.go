package jetstreampoc

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/inboxtransport"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// The barrier delays each worker only after a real broker lookup has
// returned missing evidence. Neither a fake broker nor timing guesses are
// used to force the competing stale reads.
type competingPublishClient struct {
	jetstream.JetStream
	arrived   chan<- struct{}
	release   <-chan struct{}
	publishes *atomic.Int32
}

func (c competingPublishClient) Stream(ctx context.Context, name string) (jetstream.Stream, error) {
	stream, err := c.JetStream.Stream(ctx, name)
	if err != nil {
		return nil, err
	}
	return &competingLookupStream{Stream: stream, arrived: c.arrived, release: c.release}, nil
}

func (c competingPublishClient) Publish(ctx context.Context, subject string, data []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	c.publishes.Add(1)
	return c.JetStream.Publish(ctx, subject, data, opts...)
}

type competingLookupStream struct {
	jetstream.Stream
	arrived chan<- struct{}
	release <-chan struct{}
	seen    bool
}

func (s *competingLookupStream) GetLastMsgForSubject(ctx context.Context, subject string) (*jetstream.RawStreamMsg, error) {
	record, err := s.Stream.GetLastMsgForSubject(ctx, subject)
	if !s.seen {
		s.seen = true
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			select {
			case s.arrived <- struct{}{}:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			select {
			case <-s.release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return record, err
}

var errCompetingSourceACKLost = errors.New("injected source ACK loss after competing publication")

type competingAckLoss struct {
	jetstream.Msg
	attempts *atomic.Int32
}

func (m competingAckLoss) DoubleAck(context.Context) error {
	m.attempts.Add(1)
	return errCompetingSourceACKLost
}

func TestRealJetStreamCompetingDeliveriesSinglePublishThenRecovery(t *testing.T) {
	repository, pool := pocRepository(t)
	js, consumer, dlq, cfg := pocNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	// The initial event is committed and projected. Both later deliveries
	// carry the same conflicting event, with actual broker redelivery.
	original := pocEvent(8971, 1)
	publishEvent(t, ctx, js, cfg.SourceSubject, original)
	if err := HandleMessage(ctx, repository, js, nextMessage(t, consumer), cfg, NewDispositionJournal(pool)); err != nil {
		t.Fatal(err)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, cfg.ConsumerName, allowPOCProjection{})
	if err != nil || !applied.Applied {
		t.Fatalf("original not applied: %+v err=%v", applied, err)
	}
	changed := original
	changed.Payload = []byte(`{"version":8972}`)
	publishEvent(t, ctx, js, cfg.SourceSubject, changed)
	first := nextMessage(t, consumer)

	// A separately connected client receives the same durable consumer's
	// redelivery while the first delivery is still unacknowledged.
	nc, err := nats.Connect(os.Getenv("NATS_POC_URL"), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js2, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	source, err := js2.Stream(ctx, cfg.SourceStream)
	if err != nil {
		t.Fatal(err)
	}
	consumer2, err := source.Consumer(ctx, cfg.SourceConsumer)
	if err != nil {
		t.Fatal(err)
	}
	second := nextMessage(t, consumer2)
	meta1, err := first.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	meta2, err := second.Metadata()
	if err != nil || meta2.Sequence.Stream != meta1.Sequence.Stream || meta2.NumDelivered < 2 {
		t.Fatalf("expected real same-sequence redelivery: first=%+v second=%+v err=%v", meta1, meta2, err)
	}

	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	results := make(chan error, 2)
	var publishes, ackAttempts atomic.Int32
	clients := []jetstream.JetStream{js, js2}
	for i, msg := range []jetstream.Msg{first, second} {
		client := competingPublishClient{JetStream: clients[i], arrived: arrived, release: release, publishes: &publishes}
		go func(client competingPublishClient, msg jetstream.Msg) {
			results <- HandleMessage(ctx, repository, client, competingAckLoss{Msg: msg, attempts: &ackAttempts}, cfg, NewDispositionJournal(pool))
		}(client, msg)
	}
	for range clients {
		select {
		case <-arrived:
		case err := <-results:
			t.Fatalf("worker returned before both real broker misses: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	close(release)
	winners, rejected := 0, 0
	for range clients {
		select {
		case err := <-results:
			switch {
			case errors.Is(err, errCompetingSourceACKLost):
				winners++
			case errors.Is(err, ErrDispositionConflict):
				rejected++
			default:
				t.Fatalf("unexpected settlement result: %v", err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if winners != 1 || rejected != 1 || publishes.Load() != 1 || ackAttempts.Load() != 1 {
		t.Fatalf("expected one real publish and one ACK attempt: winners=%d rejected=%d publishes=%d ackAttempts=%d", winners, rejected, publishes.Load(), ackAttempts.Load())
	}

	// The only ACK attempt was lost. The next real delivery must reconcile
	// retained broker evidence, not acquire a new publication claim.
	replay := nextMessage(t, consumer)
	meta3, err := replay.Metadata()
	if err != nil || meta3.Sequence.Stream != meta1.Sequence.Stream || meta3.NumDelivered < 3 {
		t.Fatalf("expected third same-sequence delivery: %+v err=%v", meta3, err)
	}
	recovery := competingPublishClient{JetStream: js, arrived: arrived, release: release, publishes: &publishes}
	if err := HandleMessage(ctx, repository, recovery, replay, cfg, NewDispositionJournal(pool)); err != nil {
		t.Fatalf("recover lost ACK without republish: %v", err)
	}
	info, err := dlq.Info(ctx)
	if err != nil || info.State.Msgs != 1 || publishes.Load() != 1 {
		t.Fatalf("unexpected broker evidence or repeated publish: info=%+v publishes=%d err=%v", info, publishes.Load(), err)
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
		t.Fatalf("unexpected durable evidence: dispositions=%d conflicts=%d confirmed=%t", dispositions, conflicts, confirmed)
	}
	raw, err := dlq.GetMsg(ctx, 1)
	if err != nil || raw == nil {
		t.Fatalf("confirmed broker record missing: %v", err)
	}
	var reason string
	if err := pool.QueryRow(ctx, "SELECT reason FROM poc_dlq_dispositions").Scan(&reason); err != nil || reason != inboxtransport.ReasonEventIDConflict {
		t.Fatalf("unexpected conflict reason: %q err=%v", reason, err)
	}
}
