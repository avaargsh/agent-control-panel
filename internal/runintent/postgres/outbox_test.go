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

	first, err := repository.ClaimOutbox(ctx, "worker-reused-id", time.Minute, 1, 3)
	if err != nil || len(first) != 1 || first[0].Attempt != 1 {
		t.Fatalf("first claim: leases=%+v err=%v", first, err)
	}
	contended, err := repository.ClaimOutbox(ctx, "worker-reused-id", time.Minute, 1, 3)
	if err != nil || len(contended) != 0 {
		t.Fatalf("active lease was claimed twice: leases=%+v err=%v", contended, err)
	}

	if _, err := pool.Exec(ctx, `UPDATE outbox_events SET lease_expires_at = clock_timestamp() - INTERVAL '1 second' WHERE event_id = $1::uuid`, event.ID); err != nil {
		t.Fatalf("expire first lease: %v", err)
	}
	reclaimed, err := repository.ClaimOutbox(ctx, "worker-reused-id", time.Minute, 1, 3)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].Attempt != 2 {
		t.Fatalf("expired lease was not reclaimed: leases=%+v err=%v", reclaimed, err)
	}
	if err := repository.AcknowledgeOutbox(ctx, first[0]); !errors.Is(err, ErrOutboxLeaseLost) {
		t.Fatalf("stale attempt ACK returned %v, want ErrOutboxLeaseLost", err)
	}
	if err := repository.AcknowledgeOutbox(ctx, reclaimed[0]); err != nil {
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

	first, err := repository.ClaimOutbox(ctx, "worker-1", time.Minute, 1, 2)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim: leases=%+v err=%v", first, err)
	}
	quarantined, err := repository.RetryOutbox(ctx, first[0], time.Minute, "PUBLISH_FAILED", 2)
	if err != nil || quarantined {
		t.Fatalf("first failed attempt: quarantined=%v err=%v", quarantined, err)
	}
	early, err := repository.ClaimOutbox(ctx, "worker-2", time.Minute, 1, 2)
	if err != nil || len(early) != 0 {
		t.Fatalf("event was claimed before its retry time: leases=%+v err=%v", early, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE outbox_events
		SET next_attempt_at = clock_timestamp() - INTERVAL '1 second'
		WHERE aggregate_id = $1
	`, intent.ID); err != nil {
		t.Fatalf("make retry eligible: %v", err)
	}
	second, err := repository.ClaimOutbox(ctx, "worker-2", time.Minute, 1, 2)
	if err != nil || len(second) != 1 || second[0].Attempt != 2 {
		t.Fatalf("second claim: leases=%+v err=%v", second, err)
	}
	quarantined, err = repository.RetryOutbox(ctx, second[0], time.Second, "PUBLISH_FAILED", 2)
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

	claimed, err := repository.ClaimOutbox(ctx, "worker-1", time.Minute, 1, 1)
	if err != nil || len(claimed) != 1 || claimed[0].Attempt != 1 {
		t.Fatalf("claim final attempt: leases=%+v err=%v", claimed, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE outbox_events SET lease_expires_at = clock_timestamp() - INTERVAL '1 second' WHERE event_id = $1::uuid`, claimed[0].Event.ID); err != nil {
		t.Fatalf("expire final lease: %v", err)
	}
	afterExpiry, err := repository.ClaimOutbox(ctx, "worker-2", time.Minute, 1, 1)
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

func TestOutboxClaimPreservesAggregateVersionOrder(t *testing.T) {
	repository, _ := testRepository(t)
	ctx := context.Background()
	intent := testIntent(206)
	firstEvent := testEvent(intent, 1, 1206, eventCreated)
	if _, inserted, err := repository.Create(ctx, intent, firstEvent); err != nil || !inserted {
		t.Fatalf("create RunIntent and first Outbox event: inserted=%v err=%v", inserted, err)
	}

	secondEvent := testEvent(intent, 2, 1207, "agent.run-intent.dispatching")
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin second Outbox event transaction: %v", err)
	}
	if err := insertEvent(ctx, tx, secondEvent); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("insert second Outbox event: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit second Outbox event: %v", err)
	}

	firstClaim, err := repository.ClaimOutbox(ctx, "ordered-worker-1", time.Minute, 10, 3)
	if err != nil {
		t.Fatalf("claim first aggregate event: %v", err)
	}
	if len(firstClaim) != 1 || firstClaim[0].Event.AggregateVersion != 1 {
		t.Fatalf("first claim must contain only aggregate version 1, got %+v", firstClaim)
	}

	// A different worker must not skip the leased v1 and publish v2.
	secondWorkerClaim, err := repository.ClaimOutbox(ctx, "ordered-worker-2", time.Minute, 10, 3)
	if err != nil {
		t.Fatalf("claim while aggregate predecessor is leased: %v", err)
	}
	if len(secondWorkerClaim) != 0 {
		t.Fatalf("later aggregate version was claimed before v1 was published: %+v", secondWorkerClaim)
	}

	if err := repository.AcknowledgeOutbox(ctx, firstClaim[0]); err != nil {
		t.Fatalf("acknowledge aggregate version 1: %v", err)
	}
	nextClaim, err := repository.ClaimOutbox(ctx, "ordered-worker-2", time.Minute, 10, 3)
	if err != nil {
		t.Fatalf("claim aggregate version 2 after v1 ACK: %v", err)
	}
	if len(nextClaim) != 1 || nextClaim[0].Event.AggregateVersion != 2 {
		t.Fatalf("expected aggregate version 2 after v1 ACK, got %+v", nextClaim)
	}
}
