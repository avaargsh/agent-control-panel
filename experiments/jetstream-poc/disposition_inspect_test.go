package jetstreampoc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

func TestRealDispositionInspectionIsReadOnlyAndDistinguishesEvidence(t *testing.T) {
	_, pool := pocRepository(t)
	js, _, dlq, cfg := pocNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	j := NewDispositionJournal(pool)
	record := dispositionRecord{
		stream: cfg.SourceStream, consumer: cfg.SourceConsumer, sequence: 1,
		hash: strings.Repeat("a", 64), reason: "EVENT_ID_CONFLICT",
		dlq: cfg.DLQStream, subject: cfg.DLQSubject + ".inspect", evidence: []byte("metadata-only evidence"),
	}
	check := func(wantJournal, wantBroker string) {
		t.Helper()
		got, err := j.InspectDisposition(ctx, js, cfg, 1)
		if err != nil || got.JournalState != wantJournal || got.BrokerState != wantBroker {
			t.Fatalf("unexpected inspection: %+v err=%v; want %s/%s", got, err, wantJournal, wantBroker)
		}
	}
	check("NOT_FOUND", "NOT_CHECKED")
	if _, _, err := j.ensure(ctx, record); err != nil {
		t.Fatal(err)
	}
	check("NOT_STARTED", "MISSING")
	if err := j.markPublishAttempt(ctx, record); err != nil {
		t.Fatal(err)
	}
	check("ATTEMPT_UNCONFIRMED", "MISSING")
	if _, err := js.Publish(ctx, record.subject, record.evidence, jetstream.WithExpectStream(cfg.DLQStream)); err != nil {
		t.Fatal(err)
	}
	check("ATTEMPT_UNCONFIRMED", "MATCHING")
	var started, confirmed bool
	if err := pool.QueryRow(ctx, "SELECT publish_started,published FROM poc_dlq_dispositions").Scan(&started, &confirmed); err != nil || !started || confirmed {
		t.Fatalf("inspection mutated journal: started=%t confirmed=%t err=%v", started, confirmed, err)
	}
	if err := j.confirm(ctx, record); err != nil {
		t.Fatal(err)
	}
	check("CONFIRMED", "MATCHING")
	raw, err := dlq.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := dlq.DeleteMsg(ctx, raw.Sequence); err != nil {
		t.Fatal(err)
	}
	check("CONFIRMED", "MISSING")
	if _, err := js.Publish(ctx, record.subject, []byte("different evidence"), jetstream.WithExpectStream(cfg.DLQStream)); err != nil {
		t.Fatal(err)
	}
	check("CONFIRMED", "MISMATCH")
	wrong := cfg
	wrong.DLQStream = "WRONG_STREAM"
	if _, err := j.InspectDisposition(ctx, js, wrong, 1); !errors.Is(err, ErrDispositionConflict) {
		t.Fatalf("wrong configured DLQ identity not rejected: %v", err)
	}
	if err := js.DeleteStream(ctx, cfg.DLQStream); err != nil {
		t.Fatal(err)
	}
	got, err := j.InspectDisposition(ctx, js, cfg, 1)
	if err == nil || got.BrokerState != "NOT_CHECKED" {
		t.Fatalf("missing stream is not a missing record: %+v err=%v", got, err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM poc_dlq_dispositions WHERE publish_started AND published").Scan(&count); err != nil || count != 1 {
		t.Fatalf("inspection changed persisted confirmation: count=%d err=%v", count, err)
	}
}
