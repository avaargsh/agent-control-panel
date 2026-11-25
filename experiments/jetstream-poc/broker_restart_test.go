package jetstreampoc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const restartBrokerImage = "nats:2.15.2@sha256:b6c40dcfe5ae9174dcafa9c43f800afb93b8b0ffcde02ac00efc6b66031d9a50"

var errRestartSourceACKLost = errors.New("injected source ACK loss before broker restart")

type restartACKLoss struct{ jetstream.Msg }

func (restartACKLoss) DoubleAck(context.Context) error { return errRestartSourceACKLost }

type noRestartPublish struct {
	jetstream.JetStream
	attempts int
}

func (j *noRestartPublish) Publish(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	j.attempts++
	return nil, errors.New("recovery must not publish again")
}

// Use a disposable broker and a named Docker volume, never the shared CI
// broker. SIGKILL and start the same container without recreating streams.
func TestRealJetStreamBrokerRestartPreservesConfirmedDLQ(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker is required for isolated broker restart")
	}
	repository, pool := pocRepository(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	name := fmt.Sprintf("acp-js-restart-%d", time.Now().UnixNano())
	volume := name + "-data"
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_ = exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run()
		_ = exec.CommandContext(cleanup, "docker", "volume", "rm", "-f", volume).Run()
	})
	docker := func(args ...string) string {
		t.Helper()
		output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v: %s", args[0], err, output)
		}
		return strings.TrimSpace(string(output))
	}
	docker("volume", "create", volume)
	docker("run", "-d", "--name", name, "-p", "127.0.0.1::4222", "-v", volume+":/data",
		restartBrokerImage, "-js", "-sd", "/data")
	connect := func() *nats.Conn {
		t.Helper()
		// Docker may allocate a different host port after a stopped
		// container is started again. Never reuse a stale port mapping.
		address := docker("port", name, "4222/tcp")
		if !strings.HasPrefix(address, "127.0.0.1:") || strings.Contains(address, "\n") {
			t.Fatalf("unexpected isolated broker address: %q", address)
		}
		ready, stop := context.WithTimeout(ctx, 20*time.Second)
		defer stop()
		var last error
		for ready.Err() == nil {
			nc, err := nats.Connect("nats://"+address, nats.NoReconnect(), nats.Timeout(time.Second))
			if err == nil {
				return nc
			}
			last = err
			select {
			case <-ready.Done():
			case <-time.After(100 * time.Millisecond):
			}
		}
		logs, _ := exec.CommandContext(ctx, "docker", "logs", "--tail", "50", name).CombinedOutput()
		t.Fatalf("isolated broker did not become ready at %s: %v; broker logs: %s", address, last, logs)
		return nil
	}

	nc := connect()
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ConsumerName: consumerID, SourceStream: "RESTART_SOURCE",
		SourceConsumer: "RESTART_DURABLE", SourceSubject: "restart.source",
		DLQStream: "RESTART_DLQ", DLQSubject: "restart.dlq",
	}
	source, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name: cfg.SourceStream, Subjects: []string{cfg.SourceSubject}, Storage: jetstream.FileStorage,
	})
	if err != nil {
		t.Fatal(err)
	}
	dlq, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name: cfg.DLQStream, Subjects: []string{cfg.DLQSubject + ".*"},
		Storage: jetstream.FileStorage, Retention: jetstream.LimitsPolicy,
		Discard: jetstream.DiscardNew, DiscardNewPerSubject: true,
		MaxMsgsPerSubject: 1, Duplicates: time.Second,
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
	original := pocEvent(8975, 1)
	publishEvent(t, ctx, js, cfg.SourceSubject, original)
	originalMessage := nextMessage(t, consumer)
	originalMeta, err := originalMessage.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if err := HandleMessage(ctx, repository, js, originalMessage, cfg, journal); err != nil {
		t.Fatal(err)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, cfg.ConsumerName, allowPOCProjection{})
	if err != nil || !applied.Applied {
		t.Fatalf("original not applied: %+v err=%v", applied, err)
	}
	changed := original
	changed.Payload = []byte(`{"version":8976}`)
	publishEvent(t, ctx, js, cfg.SourceSubject, changed)
	first := nextMessage(t, consumer)
	meta, err := first.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if err := HandleMessage(ctx, repository, js, restartACKLoss{first}, cfg, journal); !errors.Is(err, errRestartSourceACKLost) {
		t.Fatalf("expected lost source ACK after confirmation: %v", err)
	}
	before, err := dlq.GetMsg(ctx, 1)
	if err != nil || before == nil {
		t.Fatalf("missing confirmed DLQ before restart: %v", err)
	}
	var confirmed bool
	if err := pool.QueryRow(ctx, "SELECT published FROM poc_dlq_dispositions").Scan(&confirmed); err != nil || !confirmed {
		t.Fatalf("missing PG confirmation before restart: %v", err)
	}

	nc.Close()
	docker("kill", "--signal=KILL", name)
	docker("start", name)
	nc2 := connect()
	defer nc2.Close()
	js2, err := jetstream.New(nc2)
	if err != nil {
		t.Fatal(err)
	}
	source2, err := js2.Stream(ctx, cfg.SourceStream)
	if err != nil {
		t.Fatal(err)
	}
	consumer2, err := source2.Consumer(ctx, cfg.SourceConsumer)
	if err != nil {
		t.Fatal(err)
	}
	dlq2, err := js2.Stream(ctx, cfg.DLQStream)
	if err != nil {
		t.Fatal(err)
	}
	after, err := dlq2.GetMsg(ctx, before.Sequence)
	if err != nil || after == nil || after.Subject != before.Subject || !bytes.Equal(after.Data, before.Data) {
		t.Fatalf("confirmed DLQ evidence changed or disappeared after broker restart: %v", err)
	}
	// The broker can roll back a previously confirmed consumer ACK on an
	// abrupt process restart. Reconcile only the known original event if
	// redelivered; never skip or ACK an unexpected message.
	recovery := &noRestartPublish{JetStream: js2}
	replay := nextMessage(t, consumer2)
	replayMeta, err := replay.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if replayMeta.Sequence.Stream == originalMeta.Sequence.Stream {
		if replayMeta.Stream != originalMeta.Stream || replayMeta.Consumer != originalMeta.Consumer ||
			replay.Subject() != originalMessage.Subject() || !bytes.Equal(replay.Data(), originalMessage.Data()) {
			t.Fatal("original replay identity or bytes changed")
		}
		if err := HandleMessage(ctx, repository, recovery, replay, cfg, NewDispositionJournal(pool)); err != nil {
			t.Fatalf("reconcile prior committed Inbox event: %v", err)
		}
		t.Log("reconciled original source delivery after broker ACK state rollback")
		replay = nextMessage(t, consumer2)
		replayMeta, err = replay.Metadata()
	}
	// An abrupt broker restart can roll back the delivery-attempt counter.
	// Identify the replay by its actual source stream, consumer, sequence,
	// subject and bytes, not by a counter that is not a durable identity.
	if err != nil || replayMeta == nil || replayMeta.Stream != meta.Stream ||
		replayMeta.Consumer != meta.Consumer || replayMeta.Sequence.Stream != meta.Sequence.Stream ||
		replay.Subject() != first.Subject() || !bytes.Equal(replay.Data(), first.Data()) {
		t.Fatalf("expected identical source replay after broker restart: %+v err=%v", replayMeta, err)
	}
	t.Logf("broker restart replay: stream_sequence=%d deliveries_before=%d deliveries_after=%d",
		replayMeta.Sequence.Stream, meta.NumDelivered, replayMeta.NumDelivered)
	if err := HandleMessage(ctx, repository, recovery, replay, cfg, NewDispositionJournal(pool)); err != nil {
		t.Fatalf("recover confirmed DLQ after broker restart: %v", err)
	}
	// A lower sequence may remain pending even if the conflict is replayed
	// first. Reconcile bounded known deliveries; never skip a pending gap.
	for attempt := 0; ; attempt++ {
		settled, err := consumer2.Info(ctx)
		if err != nil || settled == nil {
			t.Fatalf("read recovered consumer state: %+v err=%v", settled, err)
		}
		if settled.AckFloor.Stream >= meta.Sequence.Stream && settled.NumAckPending == 0 && settled.NumPending == 0 {
			break
		}
		if attempt >= 4 {
			t.Fatalf("source ACK did not settle recovered deliveries: %+v", settled)
		}
		if settled.NumAckPending == 0 && settled.NumPending == 0 {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		pending := nextMessage(t, consumer2)
		pm, err := pending.Metadata()
		if err != nil || pm == nil || pm.Stream != meta.Stream || pm.Consumer != meta.Consumer {
			t.Fatalf("unexpected pending delivery identity: %+v err=%v", pm, err)
		}
		switch pm.Sequence.Stream {
		case originalMeta.Sequence.Stream:
			if pending.Subject() != originalMessage.Subject() || !bytes.Equal(pending.Data(), originalMessage.Data()) {
				t.Fatal("pending original bytes changed")
			}
		case meta.Sequence.Stream:
			if pending.Subject() != first.Subject() || !bytes.Equal(pending.Data(), first.Data()) {
				t.Fatal("pending conflict bytes changed")
			}
		default:
			t.Fatalf("unexpected pending stream sequence: %d", pm.Sequence.Stream)
		}
		if err := HandleMessage(ctx, repository, recovery, pending, cfg, NewDispositionJournal(pool)); err != nil {
			t.Fatalf("reconcile pending delivery after broker restart: %v", err)
		}
		t.Logf("reconciled pending stream sequence=%d", pm.Sequence.Stream)
	}
	info, err := dlq2.Info(ctx)
	if err != nil || info.State.Msgs != 1 || recovery.attempts != 0 {
		t.Fatalf("duplicate DLQ after restart: info=%+v publish attempts=%d err=%v", info, recovery.attempts, err)
	}
	var inboxRows, cursorVersion int
	var inboxState string
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM inbox_events").Scan(&inboxRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT state FROM inbox_events WHERE consumer_name=$1 AND event_id=$2::uuid", cfg.ConsumerName, original.ID).Scan(&inboxState); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT last_applied_version FROM inbox_cursors WHERE consumer_name=$1 AND tenant_id=$2 AND aggregate_id=$3", cfg.ConsumerName, original.TenantID, original.AggregateID).Scan(&cursorVersion); err != nil {
		t.Fatal(err)
	}
	if inboxRows != 1 || inboxState != "APPLIED" || cursorVersion != 1 {
		t.Fatalf("unexpected Inbox state after broker restart: rows=%d state=%s cursor=%d", inboxRows, inboxState, cursorVersion)
	}
	var dispositions, conflicts int
	if err := pool.QueryRow(ctx, "SELECT count(*), bool_and(published) FROM poc_dlq_dispositions").Scan(&dispositions, &confirmed); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM inbox_event_conflicts").Scan(&conflicts); err != nil {
		t.Fatal(err)
	}
	if dispositions != 1 || conflicts != 1 || !confirmed {
		t.Fatalf("unexpected PG evidence after restart: dispositions=%d conflicts=%d confirmed=%t", dispositions, conflicts, confirmed)
	}
}
