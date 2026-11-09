// Package runtimeinspect owns the read-only authenticated Runtime inspection
// adapter and a narrow ACP RunIntent reconciliation transaction boundary.
// Reconciliation never calls Runtime StartRun or promotes uncertain absence.
package runtimeinspect

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

var ErrNotReconcilable = errors.New("RunIntent is not UNKNOWN and cannot be reconciled")

type reconcileStore interface {
	Get(context.Context, string, string) (runintent.Intent, error)
	CompareAndSwap(context.Context, string, string, uint64, runintent.Intent, runpg.Event) (runintent.Intent, error)
}

type reconcileInspector interface {
	Inspect(context.Context, InspectRequest) (Inspection, error)
}

// ReconcileOnce is an explicit, bounded unit of recovery against the
// authoritative ACP PostgreSQL store and authenticated Runtime Inspect API.
// The caller must schedule and supervise this method; it is not a dispatcher,
// service loop, production principal/policy issuer or Temporal start adapter.
//
// An already ACCEPTED RunIntent is a no-op. Anything other than UNKNOWN is
// refused. An unavailable or uncertain Runtime lookup returns the intent to
// UNKNOWN, never PENDING, so another StartRun cannot be triggered by absence.
func ReconcileOnce(ctx context.Context, store reconcileStore, inspector reconcileInspector, tenantID, intentID, owner string, ttl time.Duration) (runintent.Intent, error) {
	if store == nil || inspector == nil || strings.TrimSpace(owner) == "" || ttl <= 0 {
		return runintent.Intent{}, ErrInvalidConfig
	}
	current, err := store.Get(ctx, tenantID, intentID)
	if err != nil {
		return runintent.Intent{}, err
	}
	if err := current.Validate(); err != nil || current.ID != intentID || current.TenantID != tenantID {
		return runintent.Intent{}, ErrInvalidResponse
	}
	if current.Status == runintent.Accepted {
		return current, nil
	}
	// A worker may crash after dispatching or claiming reconciliation.
	// PostgreSQL clock_timestamp() under the row lock is the sole authority
	// for lease expiry, not this process's potentially skewed wall clock.
	// Domain ExpireLease constructs a fenced proposal; a live lease is
	// refused by the database CAS before any Outbox event is committed.
	if current.Status == runintent.Dispatching || current.Status == runintent.Reconciling {
		expirationCheck := time.Now().UTC()
		if expirationCheck.Before(current.LeaseExpiresAt) {
			expirationCheck = current.LeaseExpiresAt
		}
		expired, err := current.ExpireLease(current.Version, expirationCheck)
		if err != nil {
			return current, err
		}
		ev, err := reconcileEvent(expired)
		if err != nil {
			return current, err
		}
		expired, err = store.CompareAndSwap(ctx, tenantID, intentID, current.Version, expired, ev)
		if errors.Is(err, runintent.ErrLeaseActive) {
			return current, ErrNotReconcilable
		}
		if err != nil {
			return current, err
		}
		current = expired
	}
	if current.Status != runintent.Unknown {
		return current, ErrNotReconcilable
	}

	claimed, err := current.BeginReconciliation(current.Version, owner, time.Now().UTC(), ttl)
	if err != nil {
		return current, err
	}
	ev, err := reconcileEvent(claimed)
	if err != nil {
		return current, err
	}
	claimed, err = store.CompareAndSwap(ctx, tenantID, intentID, current.Version, claimed, ev)
	if err != nil {
		return current, err
	}

	inspected, inspectErr := inspector.Inspect(ctx, InspectRequest{
		TenantID: current.TenantID, RunIntentID: current.ID, RequestDigest: current.RequestDigest,
	})
	result := runintent.ReconciliationResult{
		TenantID: current.TenantID, RunIntentID: current.ID, RequestDigest: current.RequestDigest,
		Kind: runintent.RuntimeIndeterminate,
	}
	if inspectErr == nil {
		switch inspected.Status {
		case Found:
			result.Kind = runintent.RuntimeFound
			result.TenantID = inspected.TenantID
			result.RunIntentID = inspected.RunIntentID
			result.RequestDigest = inspected.RequestDigest
			result.RunID = inspected.RunID
			result.WorkflowID = inspected.WorkflowID
		case AbsentUncertain:
			// No final-absence proof exists in this Runtime protocol.
		default:
			inspectErr = ErrInvalidResponse
		}
	}
	// Authenticated Runtime HTTP 409 is an authoritative correlation
	// conflict, not a network timeout or an uncertain absence. Persist a
	// terminal manual-review transition with its own Outbox evidence.
	if errors.Is(inspectErr, ErrRemoteConflict) {
		result.Kind = runintent.RuntimeConflict
		result.ReasonCode = "RUNTIME_STATE_CONFLICT"
	}

	next, err := claimed.ApplyReconciliationResult(
		claimed.Version, claimed.LeaseOwner, claimed.FenceToken, time.Now().UTC(), result,
	)
	if err != nil {
		return claimed, err
	}
	ev, err = reconcileEvent(next)
	if err != nil {
		return claimed, err
	}
	persisted, err := store.CompareAndSwap(ctx, tenantID, intentID, claimed.Version, next, ev)
	if err != nil {
		return claimed, err
	}
	return persisted, inspectErr
}

// Each state change is durably paired with one immutable Outbox envelope in
// the same PostgreSQL transaction by the existing Repository.CompareAndSwap.
func reconcileEvent(intent runintent.Intent) (runpg.Event, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return runpg.Event{}, fmt.Errorf("create reconciliation event identity: %w", err)
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	payload, err := json.Marshal(map[string]string{"run_intent_id": intent.ID})
	if err != nil {
		return runpg.Event{}, err
	}
	return runpg.Event{
		ID:            fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]),
		Producer:      "agent-control-panel",
		Type:          "agent.run-intent." + strings.ReplaceAll(strings.ToLower(string(intent.Status)), "_", "-"),
		SchemaVersion: 1, TenantID: intent.TenantID, AggregateType: "run_intent",
		AggregateID: intent.ID, AggregateVersion: intent.Version,
		OccurredAt: time.Now().UTC(), CorrelationID: intent.ID,
		Payload: payload,
	}, nil
}
