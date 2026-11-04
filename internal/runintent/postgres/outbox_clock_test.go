package postgres

import (
	"context"
	"testing"
	"time"
)

func TestClaimOutboxUsesDatabaseClockForEligibilityAndLeaseExpiry(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(207)
	event := testEvent(intent, 1, 1207, eventCreated)
	if _, inserted, err := repository.Create(ctx, intent, event); err != nil || !inserted {
		t.Fatalf("create RunIntent and Outbox event: inserted=%v err=%v", inserted, err)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE outbox_events
		SET next_attempt_at = clock_timestamp() + INTERVAL '1 hour'
		WHERE event_id = $1::uuid
	`, event.ID); err != nil {
		t.Fatalf("defer Outbox event: %v", err)
	}

	// A future retry timestamp must remain ineligible. ClaimOutbox has no
	// caller-supplied clock; PostgreSQL decides eligibility and lease expiry.
	claims, err := repository.ClaimOutbox(ctx, "clock-skew-worker", time.Minute, 1, 3)
	if err != nil {
		t.Fatalf("claim with skewed client clock: %v", err)
	}
	if len(claims) != 0 {
		t.Fatalf("client clock skew bypassed next_attempt_at: claimed %+v", claims)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE outbox_events
		SET next_attempt_at = clock_timestamp() - INTERVAL '1 second'
		WHERE event_id = $1::uuid
	`, event.ID); err != nil {
		t.Fatalf("make Outbox event eligible: %v", err)
	}
	claims, err = repository.ClaimOutbox(ctx, "clock-skew-worker", time.Minute, 1, 3)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim eligible Outbox event: claims=%+v err=%v", claims, err)
	}

	var leaseWithinBound bool
	if err := pool.QueryRow(ctx, `
		SELECT lease_expires_at > clock_timestamp()
		   AND lease_expires_at <= clock_timestamp() + INTERVAL '2 minutes'
		FROM outbox_events
		WHERE event_id = $1::uuid
	`, event.ID).Scan(&leaseWithinBound); err != nil {
		t.Fatalf("inspect persisted lease expiry: %v", err)
	}
	if !leaseWithinBound {
		t.Fatal("lease expiry was derived from the client clock instead of the PostgreSQL clock")
	}
}
