package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type stubEventPublisher struct {
	err       error
	published []Event
}

func (p *stubEventPublisher) Publish(ctx context.Context, event Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.published = append(p.published, event)
	return p.err
}

func TestRetryDelayUsesCappedExponentialBackoff(t *testing.T) {
	base := 2 * time.Second
	maximum := 10 * time.Second
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 1, want: 2 * time.Second},
		{attempt: 2, want: 4 * time.Second},
		{attempt: 3, want: 8 * time.Second},
		{attempt: 4, want: 10 * time.Second},
		{attempt: 5, want: 10 * time.Second},
	}
	for _, test := range tests {
		if got := retryDelay(test.attempt, base, maximum); got != test.want {
			t.Errorf("retryDelay(%d) = %s, want %s", test.attempt, got, test.want)
		}
	}
}

func TestRetryDelayDoesNotOverflowForLargeAttempt(t *testing.T) {
	if got := retryDelay(1000, time.Second, 5*time.Minute); got != 5*time.Minute {
		t.Fatalf("retryDelay(1000) = %s, want cap %s", got, 5*time.Minute)
	}
}

func TestNewOutboxDispatcherRejectsUnsafeConfiguration(t *testing.T) {
	repository := &Repository{pool: &pgxpool.Pool{}}
	tests := []struct {
		name    string
		options OutboxDispatcherOptions
	}{
		{
			name: "blank owner",
			options: OutboxDispatcherOptions{
				BatchSize: 1, LeaseTTL: time.Minute, PublishTimeout: time.Second,
				MaxAttempts: 3, BaseBackoff: time.Second, MaxBackoff: time.Minute, PollInterval: time.Second,
			},
		},
		{
			name: "publish timeout exceeds lease",
			options: OutboxDispatcherOptions{
				Owner: "worker-1", BatchSize: 1, LeaseTTL: time.Second, PublishTimeout: time.Second,
				MaxAttempts: 3, BaseBackoff: time.Second, MaxBackoff: time.Minute, PollInterval: time.Second,
			},
		},
		{
			name: "unbounded batch",
			options: OutboxDispatcherOptions{
				Owner: "worker-1", BatchSize: maxOutboxBatchSize + 1, LeaseTTL: time.Minute, PublishTimeout: time.Second,
				MaxAttempts: 3, BaseBackoff: time.Second, MaxBackoff: time.Minute, PollInterval: time.Second,
			},
		},
		{
			name: "batch cannot finish before lease expiry",
			options: OutboxDispatcherOptions{
				Owner: "worker-1", BatchSize: 10, LeaseTTL: 30 * time.Second, PublishTimeout: 3 * time.Second,
				MaxAttempts: 3, BaseBackoff: time.Second, MaxBackoff: time.Minute, PollInterval: time.Second,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewOutboxDispatcher(repository, &stubEventPublisher{}, test.options); err == nil {
				t.Fatal("NewOutboxDispatcher unexpectedly accepted invalid configuration")
			}
		})
	}
}

func TestOutboxDispatcherPublishesAndAcknowledges(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(201)
	if _, inserted, err := repository.Create(ctx, intent, testEvent(intent, 1, 1201, eventCreated)); err != nil || !inserted {
		t.Fatalf("create RunIntent and Outbox event: inserted=%v err=%v", inserted, err)
	}

	publisher := &stubEventPublisher{}
	dispatcher, err := NewOutboxDispatcher(repository, publisher, OutboxDispatcherOptions{
		Owner: "dispatcher-1", BatchSize: 10, LeaseTTL: time.Minute, PublishTimeout: 5 * time.Second,
		MaxAttempts: 3, BaseBackoff: time.Second, MaxBackoff: time.Minute, PollInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("create dispatcher: %v", err)
	}
	result, err := dispatcher.DispatchOnce(ctx)
	if err != nil {
		t.Fatalf("dispatch Outbox: %v", err)
	}
	if result.Claimed != 1 || result.Published != 1 || result.Retried != 0 || result.Quarantined != 0 {
		t.Fatalf("unexpected dispatch result: %+v", result)
	}
	if len(publisher.published) != 1 || publisher.published[0].ID != testEvent(intent, 1, 1201, eventCreated).ID {
		t.Fatalf("publisher received unexpected events: %+v", publisher.published)
	}
	var state string
	var hasPublishedAt bool
	if err := pool.QueryRow(ctx, "SELECT delivery_state, published_at IS NOT NULL FROM outbox_events WHERE aggregate_id = $1", intent.ID).Scan(&state, &hasPublishedAt); err != nil {
		t.Fatalf("read published Outbox row: %v", err)
	}
	if state != "PUBLISHED" || !hasPublishedAt {
		t.Fatalf("Outbox event was not acknowledged: state=%q hasPublishedAt=%v", state, hasPublishedAt)
	}
}

func TestOutboxDispatcherRetriesWithoutPersistingPublisherError(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(202)
	if _, inserted, err := repository.Create(ctx, intent, testEvent(intent, 1, 1202, eventCreated)); err != nil || !inserted {
		t.Fatalf("create RunIntent and Outbox event: inserted=%v err=%v", inserted, err)
	}

	publisher := &stubEventPublisher{err: errors.New("authorization=secret-value")}
	dispatcher, err := NewOutboxDispatcher(repository, publisher, OutboxDispatcherOptions{
		Owner: "dispatcher-1", BatchSize: 10, LeaseTTL: time.Minute, PublishTimeout: 5 * time.Second,
		MaxAttempts: 2, BaseBackoff: time.Minute, MaxBackoff: time.Hour, PollInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("create dispatcher: %v", err)
	}
	result, err := dispatcher.DispatchOnce(ctx)
	if err != nil {
		t.Fatalf("failed transport should be persisted as a retry: %v", err)
	}
	if result.Claimed != 1 || result.Published != 0 || result.Retried != 1 || result.Quarantined != 0 {
		t.Fatalf("unexpected retry result: %+v", result)
	}

	var state, errorCode string
	var attempts int
	if err := pool.QueryRow(ctx,
		"SELECT delivery_state, attempts, last_error_code FROM outbox_events WHERE aggregate_id = $1",
		intent.ID,
	).Scan(&state, &attempts, &errorCode); err != nil {
		t.Fatalf("read retried Outbox row: %v", err)
	}
	if state != "PENDING" || attempts != 1 || errorCode != "PUBLISH_FAILED" {
		t.Fatalf("unexpected persisted retry: state=%q attempts=%d errorCode=%q", state, attempts, errorCode)
	}
	if strings.Contains(errorCode, "secret-value") {
		t.Fatal("publisher error text leaked into persisted Outbox error code")
	}

	// A later successful delivery clears the transient failure code.
	publisher.err = nil
	if _, err := pool.Exec(ctx, `
		UPDATE outbox_events
		SET next_attempt_at = clock_timestamp() - INTERVAL '1 second'
		WHERE aggregate_id = $1
	`, intent.ID); err != nil {
		t.Fatalf("make retry eligible: %v", err)
	}
	result, err = dispatcher.DispatchOnce(ctx)
	if err != nil || result.Claimed != 1 || result.Published != 1 {
		t.Fatalf("successful retry: result=%+v err=%v", result, err)
	}
	var recoveredState string
	var errorCleared bool
	if err := pool.QueryRow(ctx, `
		SELECT delivery_state, last_error_code IS NULL
		FROM outbox_events WHERE aggregate_id = $1
	`, intent.ID).Scan(&recoveredState, &errorCleared); err != nil {
		t.Fatalf("read recovered Outbox row: %v", err)
	}
	if recoveredState != "PUBLISHED" || !errorCleared {
		t.Fatalf("successful retry retained failure state: state=%q errorCleared=%v", recoveredState, errorCleared)
	}
}

func TestOutboxClaimFencesExpiredWorkerLease(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(203)
	event := testEvent(intent, 1, 1203, eventCreated)
	if _, inserted, err := repository.Create(ctx, intent, event); err != nil || !inserted {
		t.Fatalf("create RunIntent and Outbox event: inserted=%v err=%v", inserted, err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	first, err := repository.ClaimOutbox(ctx, "worker-reused-id", now, time.Minute, 1, 3)
	if err != nil || len(first) != 1 || first[0].Attempt != 1 {
		t.Fatalf("first claim: leases=%+v err=%v", first, err)
	}
	contended, err := repository.ClaimOutbox(ctx, "worker-reused-id", now.Add(30*time.Second), time.Minute, 1, 3)
	if err != nil || len(contended) != 0 {
		t.Fatalf("active lease was claimed twice: leases=%+v err=%v", contended, err)
	}

	reclaimed, err := repository.ClaimOutbox(ctx, "worker-reused-id", now.Add(time.Minute+time.Second), time.Minute, 1, 3)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].Attempt != 2 {
		t.Fatalf("expired lease was not reclaimed: leases=%+v err=%v", reclaimed, err)
	}
	if err := repository.AcknowledgeOutbox(ctx, first[0], now.Add(time.Minute+2*time.Second)); !errors.Is(err, ErrOutboxLeaseLost) {
		t.Fatalf("stale attempt ACK returned %v, want ErrOutboxLeaseLost", err)
	}
	if err := repository.AcknowledgeOutbox(ctx, reclaimed[0], now.Add(time.Minute+2*time.Second)); err != nil {
		t.Fatalf("current attempt ACK failed: %v", err)
	}

	var state string
	if err := pool.QueryRow(ctx, "SELECT delivery_state FROM outbox_events WHERE aggregate_id = $1", intent.ID).Scan(&state); err != nil {
		t.Fatalf("read acknowledged Outbox row: %v", err)
	}
	if state != "PUBLISHED" {
		t.Fatalf("delivery state = %q, want PUBLISHED", state)
	}
}

func TestOutboxRetryQuarantinesAfterAttemptBudget(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(204)
	if _, inserted, err := repository.Create(ctx, intent, testEvent(intent, 1, 1204, eventCreated)); err != nil || !inserted {
		t.Fatalf("create RunIntent and Outbox event: inserted=%v err=%v", inserted, err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	first, err := repository.ClaimOutbox(ctx, "worker-1", now, time.Minute, 1, 2)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim: leases=%+v err=%v", first, err)
	}
	retryAt := now.Add(time.Minute)
	quarantined, err := repository.RetryOutbox(ctx, first[0], retryAt, "PUBLISH_FAILED", 2)
	if err != nil || quarantined {
		t.Fatalf("first failed attempt: quarantined=%v err=%v", quarantined, err)
	}
	early, err := repository.ClaimOutbox(ctx, "worker-2", retryAt.Add(-time.Second), time.Minute, 1, 2)
	if err != nil || len(early) != 0 {
		t.Fatalf("event was claimed before its retry time: leases=%+v err=%v", early, err)
	}
	second, err := repository.ClaimOutbox(ctx, "worker-2", retryAt, time.Minute, 1, 2)
	if err != nil || len(second) != 1 || second[0].Attempt != 2 {
		t.Fatalf("second claim: leases=%+v err=%v", second, err)
	}
	quarantined, err = repository.RetryOutbox(ctx, second[0], retryAt.Add(time.Second), "PUBLISH_FAILED", 2)
	if err != nil || !quarantined {
		t.Fatalf("attempt budget exhaustion: quarantined=%v err=%v", quarantined, err)
	}

	var state string
	if err := pool.QueryRow(ctx, "SELECT delivery_state FROM outbox_events WHERE aggregate_id = $1", intent.ID).Scan(&state); err != nil {
		t.Fatalf("read quarantined Outbox row: %v", err)
	}
	if state != "QUARANTINED" {
		t.Fatalf("delivery state = %q, want QUARANTINED", state)
	}
}

func TestOutboxExpiredLeaseAtAttemptLimitIsQuarantined(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(205)
	if _, inserted, err := repository.Create(ctx, intent, testEvent(intent, 1, 1205, eventCreated)); err != nil || !inserted {
		t.Fatalf("create RunIntent and Outbox event: inserted=%v err=%v", inserted, err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	claimed, err := repository.ClaimOutbox(ctx, "worker-1", now, time.Minute, 1, 1)
	if err != nil || len(claimed) != 1 || claimed[0].Attempt != 1 {
		t.Fatalf("claim final attempt: leases=%+v err=%v", claimed, err)
	}
	afterExpiry, err := repository.ClaimOutbox(ctx, "worker-2", now.Add(time.Minute+time.Second), time.Minute, 1, 1)
	if err != nil || len(afterExpiry) != 0 {
		t.Fatalf("expired final lease should be quarantined, not reclaimed: leases=%+v err=%v", afterExpiry, err)
	}

	var state, errorCode string
	if err := pool.QueryRow(ctx,
		"SELECT delivery_state, last_error_code FROM outbox_events WHERE aggregate_id = $1",
		intent.ID,
	).Scan(&state, &errorCode); err != nil {
		t.Fatalf("read exhausted Outbox row: %v", err)
	}
	if state != "QUARANTINED" || errorCode != "OUTBOX_ATTEMPTS_EXHAUSTED" {
		t.Fatalf("unexpected exhausted lease: state=%q errorCode=%q", state, errorCode)
	}
}

func TestOutboxLeaseValidationRejectsBadErrorCodes(t *testing.T) {
	if validOutboxErrorCode("PUBLISH_FAILED") != true ||
		validOutboxErrorCode("contains secret") != false ||
		validOutboxErrorCode(strings.Repeat("A", 129)) != false {
		t.Fatal(fmt.Sprintf("unexpected Outbox error code validation"))
	}
}
