package runtimeinspect

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

func TestInputBoundReconciliationNeverUsesLegacyLookup(t *testing.T) {
	intent := unknownRecoveryFixture(t)
	raw := []byte(`{"task":"observe"}`)
	var err error
	intent.RequestDigest, err = runintent.ExecutionInputDigest(intent, raw)
	if err != nil {
		t.Fatal(err)
	}
	store := &dispatchInputFixture{recoveryStoreFixture: &recoveryStoreFixture{intent: intent}, raw: raw}
	calls := 0
	legacy := inspectionFixture(func(_ context.Context, req InspectRequest) (Inspection, error) {
		calls++
		return Inspection{
			Status: Found, TenantID: req.TenantID, RunIntentID: req.RunIntentID,
			RequestDigest: req.RequestDigest, RunID: testRunID, WorkflowID: "agent-run/v1/" + testRunID,
		}, nil
	})
	got, err := ReconcileOnce(context.Background(), store, legacy, intent.TenantID, intent.ID, "reconciler", time.Minute)
	if !errors.Is(err, ErrInvalidConfig) || got.Status != runintent.Unknown || calls != 0 {
		t.Fatalf("weak lookup promoted an input-bound Run: status=%s err=%v calls=%d", got.Status, err, calls)
	}
}
