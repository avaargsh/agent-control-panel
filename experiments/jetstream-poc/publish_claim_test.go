package jetstreampoc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Both workers observe the same unclaimed durable intent before either
// attempts publication. Only one may obtain the right to publish.
func TestDispositionJournalGrantsOnlyOnePublishClaim(t *testing.T) {
	_, pool := pocRepository(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	record := dispositionRecord{
		stream: "source", consumer: "consumer", sequence: 1,
		hash: strings.Repeat("a", 64), reason: "EVENT_ID_CONFLICT",
		dlq: "dlq", subject: "dlq.claim", evidence: []byte("immutable evidence"),
	}
	workers := []*DispositionJournal{NewDispositionJournal(pool), NewDispositionJournal(pool)}
	for _, worker := range workers {
		confirmed, attempted, err := worker.ensure(ctx, record)
		if err != nil || confirmed || attempted {
			t.Fatalf("expected unclaimed intent: confirmed=%t attempted=%t err=%v", confirmed, attempted, err)
		}
	}

	start := make(chan struct{})
	results := make(chan error, len(workers))
	for _, worker := range workers {
		go func(journal *DispositionJournal) {
			<-start
			results <- journal.markPublishAttempt(ctx, record)
		}(worker)
	}
	close(start)
	winners, rejected := 0, 0
	for range workers {
		err := <-results
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrDispositionConflict):
			rejected++
		default:
			t.Fatalf("unexpected publish claim error: %v", err)
		}
	}
	if winners != 1 || rejected != 1 {
		t.Fatalf("publish claim must be exclusive: winners=%d rejected=%d", winners, rejected)
	}
	confirmed, attempted, err := workers[0].ensure(ctx, record)
	if err != nil || confirmed || !attempted {
		t.Fatalf("claim must persist without inventing confirmation: confirmed=%t attempted=%t err=%v", confirmed, attempted, err)
	}
	if err := workers[1].markPublishAttempt(ctx, record); !errors.Is(err, ErrDispositionConflict) {
		t.Fatalf("stale worker reacquired publish claim: %v", err)
	}
}
