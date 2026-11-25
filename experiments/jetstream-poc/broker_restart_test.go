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
	if err := HandleMessage(ctx, repository, js, nextMessage(t, consumer), cfg, journal); err != nil {
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
	replay := nextMessage(t, consumer2)
	replayMeta, err := replay.Metadata()
	if err != nil || replayMeta.Sequence.Stream != meta.Sequence.Stream || replayMeta.NumDelivered < 2 {
		t.Fatalf("expected same source redelivery after broker restart: %+v err=%v", replayMeta, err)
	}
	recovery := &noRestartPublish{JetStream: js2}
	if err := HandleMessage(ctx, repository, recovery, replay, cfg, NewDispositionJournal(pool)); err != nil {
		t.Fatalf("recover confirmed DLQ after broker restart: %v", err)
	}
	info, err := dlq2.Info(ctx)
	if err != nil || info.State.Msgs != 1 || recovery.attempts != 0 {
		t.Fatalf("duplicate DLQ after restart: info=%+v publish attempts=%d err=%v", info, recovery.attempts, err)
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
