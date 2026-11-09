package runtimeinspect

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

type acceptFunc func(context.Context, runintent.Intent) (runintent.DispatchOutcome, error)

func (f acceptFunc) Accept(ctx context.Context, intent runintent.Intent) (runintent.DispatchOutcome, error) {
	return f(ctx, intent)
}

func pendingDispatchFixture(t *testing.T) runintent.Intent {
	t.Helper()
	intent := unknownRecoveryFixture(t)
	intent.Version = 1
	intent.FenceToken = 0
	intent.Status = runintent.Pending
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestDispatchOnceLostACKPersistsUNKNOWNAndNeverRetriesStart(t *testing.T) {
	intent := pendingDispatchFixture(t)
	store := &recoveryStoreFixture{intent: intent}
	count := 0
	transportFailure := errors.New("HTTP ACK missing after request")
	acceptor := acceptFunc(func(_ context.Context, got runintent.Intent) (runintent.DispatchOutcome, error) {
		count++
		if got.Status != runintent.Dispatching || got.ID != intent.ID || got.RequestDigest != intent.RequestDigest {
			t.Fatalf("accept called outside committed dispatch lease: %+v", got)
		}
		if store.intent.Status != runintent.Dispatching {
			t.Fatal("network call preceded durable claim")
		}
		return runintent.DispatchOutcome{}, transportFailure
	})
	got, err := DispatchOnce(context.Background(), store, acceptor, intent.TenantID, intent.ID, "dispatcher-1", time.Minute)
	if !errors.Is(err, transportFailure) || got.Status != runintent.Unknown || got.Version != 3 || got.FenceToken != 1 {
		t.Fatalf("lost ACK must commit UNKNOWN: %+v %v", got, err)
	}
	if count != 1 || len(store.events) != 2 ||
		store.events[0].Type != "agent.run-intent.dispatching" ||
		store.events[1].Type != "agent.run-intent.unknown" {
		t.Fatalf("wrong dispatch/outbox cardinality: requests=%d events=%+v", count, store.events)
	}
	again, err := DispatchOnce(context.Background(), store, acceptor, intent.TenantID, intent.ID, "dispatcher-2", time.Minute)
	if !errors.Is(err, ErrNotDispatchable) || again.Status != runintent.Unknown || count != 1 || len(store.events) != 2 {
		t.Fatalf("unknown status triggered duplicate StartRun: %+v %v", again, err)
	}
}

func TestDispatchOnceMatchedRuntimeReceiptIsIdempotent(t *testing.T) {
	intent := pendingDispatchFixture(t)
	store := &recoveryStoreFixture{intent: intent}
	calls := 0
	acceptor := acceptFunc(func(_ context.Context, got runintent.Intent) (runintent.DispatchOutcome, error) {
		calls++
		return runintent.DispatchOutcome{
			TenantID: got.TenantID, RunIntentID: got.ID, RequestDigest: got.RequestDigest,
			Kind: runintent.DispatchAccepted, RunID: "runtime-run-1",
			WorkflowID: "agent-run/v1/runtime-run-1",
		}, nil
	})
	got, err := DispatchOnce(context.Background(), store, acceptor, intent.TenantID, intent.ID, "dispatcher-1", time.Minute)
	if err != nil || got.Status != runintent.Accepted || got.RunID != "runtime-run-1" || len(store.events) != 2 {
		t.Fatalf("valid receipt not persisted: %+v %v", got, err)
	}
	second, err := DispatchOnce(context.Background(), store, acceptor, intent.TenantID, intent.ID, "dispatcher-2", time.Minute)
	if err != nil || second.RunID != got.RunID || calls != 1 || len(store.events) != 2 {
		t.Fatalf("accepted Run dispatched again: %+v %v calls=%d", second, err, calls)
	}
}

func TestDispatchOnceMismatchedReceiptEntersManualReview(t *testing.T) {
	intent := pendingDispatchFixture(t)
	store := &recoveryStoreFixture{intent: intent}
	acceptor := acceptFunc(func(_ context.Context, got runintent.Intent) (runintent.DispatchOutcome, error) {
		return runintent.DispatchOutcome{
			TenantID: "other-tenant", RunIntentID: got.ID, RequestDigest: got.RequestDigest,
			Kind: runintent.DispatchAccepted, RunID: "foreign-run",
			WorkflowID: "agent-run/v1/foreign-run",
		}, nil
	})
	got, err := DispatchOnce(context.Background(), store, acceptor, intent.TenantID, intent.ID, "dispatcher-1", time.Minute)
	if err != nil || got.Status != runintent.ManualReview || got.ManualReviewCode != "RUNTIME_RECEIPT_MISMATCH" || len(store.events) != 2 {
		t.Fatalf("foreign Runtime receipt accepted: %+v %v", got, err)
	}
}

func TestDispatchOnceUnrecognizedReceiptKindPersistsUnknown(t *testing.T) {
	intent := pendingDispatchFixture(t)
	store := &recoveryStoreFixture{intent: intent}
	calls := 0
	acceptor := acceptFunc(func(_ context.Context, got runintent.Intent) (runintent.DispatchOutcome, error) {
		calls++
		return runintent.DispatchOutcome{
			TenantID: got.TenantID, RunIntentID: got.ID, RequestDigest: got.RequestDigest,
			Kind:  runintent.DispatchOutcomeKind("UNRECOGNIZED"),
			RunID: "caller-controlled-run", WorkflowID: "agent-run/v1/caller-controlled-run",
		}, nil
	})
	got, err := DispatchOnce(context.Background(), store, acceptor,
		intent.TenantID, intent.ID, "dispatcher-1", time.Minute)
	if !errors.Is(err, ErrInvalidResponse) || got.Status != runintent.Unknown ||
		store.intent.Status != runintent.Unknown || got.RunID != "" || got.WorkflowID != "" ||
		len(store.events) != 2 || store.events[1].Type != "agent.run-intent.unknown" {
		t.Fatalf("unknown Runtime receipt escaped fail-closed UNKNOWN persistence: %+v %+v events=%+v err=%v",
			got, store.intent, store.events, err)
	}
	replay, err := DispatchOnce(context.Background(), store, acceptor,
		intent.TenantID, intent.ID, "dispatcher-2", time.Minute)
	if !errors.Is(err, ErrNotDispatchable) || replay.Status != runintent.Unknown || calls != 1 {
		t.Fatalf("unknown receipt permitted a second StartRun: %+v err=%v calls=%d", replay, err, calls)
	}
}

type cancellationAwareDispatchStore struct {
	*recoveryStoreFixture
}

func (s *cancellationAwareDispatchStore) CompareAndSwap(ctx context.Context, tenantID, intentID string, version uint64, next runintent.Intent, event runpg.Event) (runintent.Intent, error) {
	if err := ctx.Err(); err != nil {
		return runintent.Intent{}, err
	}
	return s.recoveryStoreFixture.CompareAndSwap(ctx, tenantID, intentID, version, next, event)
}

// A network call may return context.Canceled after Runtime commits StartRun.
// ACP must use a bounded cleanup context to persist UNKNOWN before returning,
// rather than reuse the canceled network context for the authoritative CAS.
func TestDispatchOnceCancellationAfterAcceptPersistsUnknown(t *testing.T) {
	intent := pendingDispatchFixture(t)
	store := &cancellationAwareDispatchStore{recoveryStoreFixture: &recoveryStoreFixture{intent: intent}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	acceptor := acceptFunc(func(_ context.Context, claimed runintent.Intent) (runintent.DispatchOutcome, error) {
		calls++
		if store.intent.Status != runintent.Dispatching {
			t.Fatal("Accept before durable DISPATCHING claim")
		}
		cancel()
		return runintent.DispatchOutcome{}, context.Canceled
	})
	got, err := DispatchOnce(ctx, store, acceptor, intent.TenantID, intent.ID, "worker-1", time.Minute)
	if !errors.Is(err, context.Canceled) || got.Status != runintent.Unknown ||
		store.intent.Status != runintent.Unknown || len(store.events) != 2 ||
		store.events[1].Type != "agent.run-intent.unknown" {
		t.Fatalf("canceled network context lost UNKNOWN persistence: got=%+v stored=%+v events=%+v err=%v", got, store.intent, store.events, err)
	}
	again, err := DispatchOnce(context.Background(), store, acceptor, intent.TenantID, intent.ID, "worker-2", time.Minute)
	if !errors.Is(err, ErrNotDispatchable) || again.Status != runintent.Unknown || calls != 1 {
		t.Fatalf("canceled request was dispatched again: %+v err=%v calls=%d", again, err, calls)
	}
}
