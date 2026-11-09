package runtimeinspect

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

func TestReconcileOnceExpiredDispatchClaimRecoversWithoutSecondStart(t *testing.T) {
	intent := pendingDispatchFixture(t)
	past := time.Now().Add(-2 * time.Minute)
	claimed, err := intent.ClaimDispatch(intent.Version, "crashed-dispatcher", past, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store := &recoveryStoreFixture{intent: claimed}
	calls := 0
	inspector := inspectionFixture(func(_ context.Context, req InspectRequest) (Inspection, error) {
		calls++
		return Inspection{
			Status: Found, TenantID: req.TenantID, RunIntentID: req.RunIntentID,
			RequestDigest: req.RequestDigest, RunID: "runtime-run-1",
			WorkflowID: "agent-run/v1/runtime-run-1",
		}, nil
	})
	got, err := ReconcileOnce(context.Background(), store, inspector,
		claimed.TenantID, claimed.ID, "restarted-reconciler", time.Minute)
	if err != nil || got.Status != runintent.Accepted || got.RunID != "runtime-run-1" {
		t.Fatalf("crashed dispatch claim not reconciled via Inspect: %+v %v", got, err)
	}
	if got.Version != claimed.Version+3 || got.FenceToken != claimed.FenceToken+2 ||
		len(store.events) != 3 || calls != 1 {
		t.Fatalf("expired dispatch did not fence original worker: %+v events=%+v calls=%d", got, store.events, calls)
	}
	for i, want := range []string{"agent.run-intent.unknown", "agent.run-intent.reconciling", "agent.run-intent.accepted"} {
		if store.events[i].Type != want {
			t.Fatalf("transition %d event = %q, want %q", i, store.events[i].Type, want)
		}
	}
	if _, err := got.ClaimDispatch(got.Version, "new-dispatcher", time.Now(), time.Minute); !errors.Is(err, runintent.ErrTransition) {
		t.Fatalf("recovery allowed a second StartRun: %v", err)
	}
}

func TestReconcileOnceDoesNotStealLiveDispatchLease(t *testing.T) {
	intent := pendingDispatchFixture(t)
	claimed, err := intent.ClaimDispatch(intent.Version, "active-dispatcher", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store := &recoveryStoreFixture{intent: claimed}
	inspector := inspectionFixture(func(context.Context, InspectRequest) (Inspection, error) {
		t.Fatal("reconcile must not call Inspect for a live dispatch lease")
		return Inspection{}, nil
	})
	got, err := ReconcileOnce(context.Background(), store, inspector,
		claimed.TenantID, claimed.ID, "competing-worker", time.Minute)
	if !errors.Is(err, ErrNotReconcilable) || got.Status != runintent.Dispatching || len(store.events) != 0 {
		t.Fatalf("live dispatch lease was stolen: %+v events=%d err=%v", got, len(store.events), err)
	}
}
