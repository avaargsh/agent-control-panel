package runtimeinspect

import (
    "context"
    "errors"
    "fmt"
    "testing"
    "time"

    "github.com/avaargsh/agent-control-panel/internal/runintent"
    runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

type recoveryStoreFixture struct {
    intent runintent.Intent
    events []runpg.Event
}

func (s *recoveryStoreFixture) Get(_ context.Context, tenantID, intentID string) (runintent.Intent, error) {
    if tenantID != s.intent.TenantID || intentID != s.intent.ID {
        return runintent.Intent{}, errors.New("wrong identity")
    }
    return s.intent, nil
}

func (s *recoveryStoreFixture) CompareAndSwap(_ context.Context, tenantID, intentID string, version uint64, next runintent.Intent, event runpg.Event) (runintent.Intent, error) {
    if tenantID != s.intent.TenantID || intentID != s.intent.ID || version != s.intent.Version || next.Version != version+1 {
        return runintent.Intent{}, errors.New("stale or unscoped CAS")
    }
    if event.AggregateVersion != next.Version || event.AggregateID != intentID || event.TenantID != tenantID || event.ID == "" {
        return runintent.Intent{}, errors.New("bad Outbox event")
    }
    s.intent = next
    s.events = append(s.events, event)
    return next, nil
}

type inspectionFixture func(context.Context, InspectRequest) (Inspection, error)

func (f inspectionFixture) Inspect(ctx context.Context, req InspectRequest) (Inspection, error) {
    return f(ctx, req)
}

func unknownRecoveryFixture(t *testing.T) runintent.Intent {
    t.Helper()
    now := time.Now().UTC()
    intent := runintent.Intent{
        ID: "00000000-0000-4000-8000-000000000001", TenantID: "tenant-1",
        PrincipalID: "principal-1", ProjectID: "project-1", AgentID: "agent-1",
        ReleaseID: "release-1", SessionID: "session-1", IdempotencyKey: "key-1",
        RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        Version: 1, Status: runintent.Pending,
    }
    leased, err := intent.ClaimDispatch(intent.Version, "dispatcher-1", now, 3*time.Minute)
    if err != nil { t.Fatal(err) }
    unknown, err := leased.RecordDispatchOutcome(leased.Version, leased.LeaseOwner, leased.FenceToken, now.Add(time.Second),
        runintent.DispatchOutcome{TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest, Kind: runintent.DispatchAmbiguous})
    if err != nil { t.Fatal(err) }
    return unknown
}

func TestReconcileOnceFoundCommitsSingleAcceptedTransition(t *testing.T) {
    intent := unknownRecoveryFixture(t)
    store := &recoveryStoreFixture{intent: intent}
    calls := 0
    inspect := inspectionFixture(func(_ context.Context, req InspectRequest) (Inspection, error) {
        calls++
        if req.TenantID != intent.TenantID || req.RunIntentID != intent.ID || req.RequestDigest != intent.RequestDigest {
            t.Fatal("Inspect did not use immutable persisted RunIntent scope")
        }
        return Inspection{Status: Found, TenantID: req.TenantID, RunIntentID: req.RunIntentID,
            RequestDigest: req.RequestDigest, RunID: "run-1", WorkflowID: "agent-run/v1/run-1"}, nil
    })
    got, err := ReconcileOnce(context.Background(), store, inspect, intent.TenantID, intent.ID, "reconciler-1", time.Minute)
    if err != nil || got.Status != runintent.Accepted || got.RunID != "run-1" || len(store.events) != 2 {
        t.Fatalf("reconcile FOUND: %+v events=%d err=%v", got, len(store.events), err)
    }
    if store.events[0].Type != "agent.run-intent.reconciling" || store.events[1].Type != "agent.run-intent.accepted" {
        t.Fatalf("wrong transition events: %+v", store.events)
    }
    again, err := ReconcileOnce(context.Background(), store, inspect, intent.TenantID, intent.ID, "reconciler-2", time.Minute)
    if err != nil || again.RunID != got.RunID || calls != 1 || len(store.events) != 2 {
        t.Fatalf("replay must not re-inspect or write: %+v events=%d calls=%d err=%v", again, len(store.events), calls, err)
    }
}

func TestReconcileOnceUncertainAbsenceNeverReissuesRun(t *testing.T) {
    intent := unknownRecoveryFixture(t)
    store := &recoveryStoreFixture{intent: intent}
    inspect := inspectionFixture(func(_ context.Context, req InspectRequest) (Inspection, error) {
        return Inspection{Status: AbsentUncertain}, nil
    })
    got, err := ReconcileOnce(context.Background(), store, inspect, intent.TenantID, intent.ID, "reconciler-1", time.Minute)
    if err != nil || got.Status != runintent.Unknown || got.Version != intent.Version+2 || len(store.events) != 2 {
        t.Fatalf("uncertain absence became final: %+v events=%d err=%v", got, len(store.events), err)
    }
    if _, err := got.ClaimDispatch(got.Version, "dispatcher-2", time.Now().UTC(), time.Minute); !errors.Is(err, runintent.ErrTransition) {
        t.Fatalf("unconfirmed absence authorized StartRun: %v", err)
    }
}

func TestReconcileOnceTransportFailurePersistsUnknown(t *testing.T) {
    intent := unknownRecoveryFixture(t)
    store := &recoveryStoreFixture{intent: intent}
    inspect := inspectionFixture(func(context.Context, InspectRequest) (Inspection, error) {
        return Inspection{}, ErrUnavailable
    })
    got, err := ReconcileOnce(context.Background(), store, inspect, intent.TenantID, intent.ID, "reconciler-1", time.Minute)
    if !errors.Is(err, ErrUnavailable) || got.Status != runintent.Unknown || store.intent.Status != runintent.Unknown ||
        len(store.events) != 2 || store.events[1].Type != "agent.run-intent.unknown" {
        t.Fatalf("transport failure mutated authority: %+v events=%d err=%v", got, len(store.events), err)
    }
}

func TestReconcileOnceInvalidFoundFailsClosed(t *testing.T) {
    intent := unknownRecoveryFixture(t)
    store := &recoveryStoreFixture{intent: intent}
    inspect := inspectionFixture(func(context.Context, InspectRequest) (Inspection, error) {
        return Inspection{Status: Found, TenantID: "tenant-foreign", RunIntentID: intent.ID,
            RequestDigest: intent.RequestDigest, RunID: "run-foreign", WorkflowID: "agent-run/v1/run-foreign"}, nil
    })
    got, err := ReconcileOnce(context.Background(), store, inspect, intent.TenantID, intent.ID, "reconciler-1", time.Minute)
    if err != nil || got.Status != runintent.ManualReview || got.ManualReviewCode != "RUNTIME_RECONCILIATION_MISMATCH" {
        t.Fatalf("foreign Runtime receipt accepted: %+v err=%v", got, err)
    }
}

func TestReconcileOnceRequiresUnknownAndNoSecondStart(t *testing.T) {
    intent := unknownRecoveryFixture(t)
    intent.Status = runintent.Pending
    store := &recoveryStoreFixture{intent: intent}
    inspect := inspectionFixture(func(context.Context, InspectRequest) (Inspection, error) {
        return Inspection{}, fmt.Errorf("Inspect must not run")
    })
    _, err := ReconcileOnce(context.Background(), store, inspect, intent.TenantID, intent.ID, "reconciler-1", time.Minute)
    if !errors.Is(err, ErrNotReconcilable) || len(store.events) != 0 {
        t.Fatalf("non-UNKNOWN was reconciled: %v", err)
    }
}
