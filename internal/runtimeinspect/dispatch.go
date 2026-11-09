package runtimeinspect

import (
	"context"
	"errors"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

// ErrNotDispatchable prevents retrying an UNKNOWN or otherwise non-PENDING
// RunIntent. Only authoritative reconciliation may resolve ambiguous outcomes.
var ErrNotDispatchable = errors.New("RunIntent is not PENDING and must not be dispatched")

// dispatchAcceptor must be a separately authenticated Runtime admission
// adapter with authoritative principal/policy issuance. This package does
// not implement or enable such an adapter for production.
type dispatchAcceptor interface {
	Accept(context.Context, runintent.Intent) (runintent.DispatchOutcome, error)
}

// DispatchOnce owns only the bounded ACP persistence sequence for one
// already-created RunIntent. A caller must supply the authenticated Runtime
// adapter and supervise scheduling, identity/policy authorization, and worker
// lifecycle. It cannot mint Runtime Run IDs or retry uncertain StartRun.
//
// The claim is committed before Accept. Any transport error or malformed
// receipt is persisted as UNKNOWN; the same request is never reissued from
// UNKNOWN. Existing PostgreSQL CAS enforces authoritative lease/fencing.
func DispatchOnce(ctx context.Context, store reconcileStore, acceptor dispatchAcceptor, tenantID, intentID, owner string, ttl time.Duration) (runintent.Intent, error) {
	if store == nil || acceptor == nil || owner == "" || ttl <= 0 {
		return runintent.Intent{}, ErrInvalidConfig
	}
	current, err := store.Get(ctx, tenantID, intentID)
	if err != nil {
		return runintent.Intent{}, err
	}
	if err := current.Validate(); err != nil || current.TenantID != tenantID || current.ID != intentID {
		return runintent.Intent{}, ErrInvalidResponse
	}
	if current.Status == runintent.Accepted {
		return current, nil
	}
	if current.Status != runintent.Pending {
		return current, ErrNotDispatchable
	}

	claimed, err := current.ClaimDispatch(current.Version, owner, time.Now().UTC(), ttl)
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

	receipt, acceptErr := acceptor.Accept(ctx, claimed)
	knownKind := receipt.Kind == runintent.DispatchAccepted ||
		receipt.Kind == runintent.DispatchRejected ||
		receipt.Kind == runintent.DispatchAmbiguous
	if acceptErr != nil || !knownKind {
		// Lost ACK or unknown receipt kind is ambiguous, never a definitive
		// rejection. Do not leave DISPATCHING waiting on an invalid receipt
		// and do not reissue StartRun from UNKNOWN.
		if acceptErr == nil {
			acceptErr = ErrInvalidResponse
		}
		receipt = runintent.DispatchOutcome{
			TenantID: claimed.TenantID, RunIntentID: claimed.ID,
			RequestDigest: claimed.RequestDigest, Kind: runintent.DispatchAmbiguous,
		}
	}
	next, err := claimed.RecordDispatchOutcome(
		claimed.Version, claimed.LeaseOwner, claimed.FenceToken, time.Now().UTC(), receipt,
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
		// The state is uncertain until a fresh authoritative read.
		return claimed, err
	}
	return persisted, acceptErr
}
