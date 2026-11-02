// Package runintent owns dispatch intent, never the executed Run lifecycle.
package runintent

import "errors"

type Status string

const (
    Pending Status = "PENDING"
    Dispatching Status = "DISPATCHING"
    Dispatched Status = "DISPATCHED"
    Unknown Status = "UNKNOWN"
    CancelRequested Status = "CANCEL_REQUESTED"
)

var (
    ErrInvalid = errors.New("invalid run intent")
    ErrStaleVersion = errors.New("stale run intent version")
    ErrTransition = errors.New("forbidden run intent transition")
)

type Intent struct {
    ID string
    TenantID string
    SessionID string
    ReleaseID string
    WorkflowID string
    Version uint64
    Status Status
}

func (i Intent) Validate() error {
    if i.ID == "" || i.TenantID == "" || i.SessionID == "" || i.ReleaseID == "" ||
        i.WorkflowID == "" || i.Version == 0 {
        return ErrInvalid
    }
    switch i.Status {
    case Pending, Dispatching, Dispatched, Unknown, CancelRequested:
        return nil
    }
    return ErrInvalid
}

// Advance is a pure transition, not a durable compare-and-swap. The store
// must atomically persist the version change and transactional outbox.
// An UNKNOWN dispatch may only become DISPATCHED after the exact workflow
// identity has been independently observed by the provider adapter.
func (i Intent) Advance(expectedVersion uint64, next Status, providerVerified bool) (Intent, error) {
    if err := i.Validate(); err != nil { return i, err }
    if i.Version != expectedVersion { return i, ErrStaleVersion }
    allowed := false
    switch i.Status {
    case Pending:
        allowed = next == Dispatching || next == CancelRequested
    case Dispatching:
        allowed = next == Dispatched || next == Unknown
    case Unknown:
        allowed = next == Dispatched && providerVerified
    case Dispatched:
        allowed = next == CancelRequested
    }
    if !allowed { return i, ErrTransition }
    i.Status = next
    i.Version++
    return i, nil
}
