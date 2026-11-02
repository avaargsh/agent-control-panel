// Package runintent owns the request to start a Run, not the Run lifecycle.
// Agent Runtime is the authority for run_id, workflow_id and attempt_id.
package runintent

import (
    "encoding/hex"
    "errors"
    "strings"
    "time"
)

type Status string

const (
    Pending      Status = "PENDING"
    Dispatching  Status = "DISPATCHING"
    Unknown      Status = "UNKNOWN"
    Reconciling  Status = "RECONCILING"
    Accepted     Status = "ACCEPTED"
    Rejected     Status = "REJECTED"
    ManualReview Status = "MANUAL_REVIEW"
)

type DispatchOutcomeKind string

const (
    DispatchAccepted  DispatchOutcomeKind = "ACCEPTED"
    DispatchRejected  DispatchOutcomeKind = "REJECTED"
    DispatchAmbiguous DispatchOutcomeKind = "AMBIGUOUS"
)

type ReconciliationKind string

const (
    RuntimeFound         ReconciliationKind = "FOUND"
    RuntimeNotFoundFinal ReconciliationKind = "NOT_FOUND_FINAL"
    RuntimeIndeterminate ReconciliationKind = "INDETERMINATE"
    RuntimeRejected      ReconciliationKind = "REJECTED"
    RuntimeConflict      ReconciliationKind = "CONFLICT"
)

// DispatchOutcome is produced by the authenticated Runtime adapter. A
// caller-supplied boolean is deliberately not accepted as verification.
type DispatchOutcome struct {
    RunIntentID   string
    RequestDigest string
    Kind          DispatchOutcomeKind
    RunID         string
    WorkflowID    string
    RejectionCode string
}

// ReconciliationResult is produced by Runtime's authoritative lookup keyed
// by RunIntentID + RequestDigest. NOT_FOUND_FINAL must come from its durable
// idempotency registry, not from an eventually-consistent workflow listing.
type ReconciliationResult struct {
    RunIntentID   string
    RequestDigest string
    Kind          ReconciliationKind
    RunID         string
    WorkflowID    string
    RejectionCode string
    ReasonCode    string
}

var (
    ErrInvalid       = errors.New("invalid run intent")
    ErrStaleVersion  = errors.New("stale run intent version")
    ErrTransition    = errors.New("forbidden run intent transition")
    ErrInvalidOutcome = errors.New("invalid runtime outcome")
    ErrStaleLease    = errors.New("stale run intent lease or fencing token")
    ErrLeaseExpired  = errors.New("run intent lease expired")
    ErrLeaseActive   = errors.New("run intent lease is still active")
)

type Intent struct {
    ID             string
    TenantID       string
    PrincipalID    string
    ProjectID      string
    AgentID        string
    ReleaseID      string
    SessionID      string
    IdempotencyKey string
    RequestDigest  string

    Version        uint64
    FenceToken     uint64
    Status         Status
    LeaseOwner     string
    LeaseExpiresAt time.Time

    // Runtime-owned identifiers are populated only from a matching receipt.
    RunID         string
    WorkflowID    string
    RejectionCode string
    ManualReviewCode string
}

func validDigest(value string) bool {
    if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
        return false
    }
    digest := strings.TrimPrefix(value, "sha256:")
    if strings.ToLower(digest) != digest {
        return false
    }
    _, err := hex.DecodeString(digest)
    return err == nil
}

func (i Intent) Validate() error {
    if strings.TrimSpace(i.ID) == "" ||
        strings.TrimSpace(i.TenantID) == "" ||
        strings.TrimSpace(i.PrincipalID) == "" ||
        strings.TrimSpace(i.ProjectID) == "" ||
        strings.TrimSpace(i.AgentID) == "" ||
        strings.TrimSpace(i.ReleaseID) == "" ||
        strings.TrimSpace(i.SessionID) == "" ||
        strings.TrimSpace(i.IdempotencyKey) == "" ||
        !validDigest(i.RequestDigest) || i.Version == 0 {
        return ErrInvalid
    }

    leased := i.Status == Dispatching || i.Status == Reconciling
    if leased {
        if strings.TrimSpace(i.LeaseOwner) == "" || i.LeaseExpiresAt.IsZero() || i.FenceToken == 0 {
            return ErrInvalid
        }
    } else if i.LeaseOwner != "" || !i.LeaseExpiresAt.IsZero() {
        return ErrInvalid
    }

    switch i.Status {
    case Pending, Dispatching, Unknown, Reconciling:
        if i.RunID != "" || i.WorkflowID != "" || i.RejectionCode != "" || i.ManualReviewCode != "" {
            return ErrInvalid
        }
    case Accepted:
        if i.RunID == "" || i.WorkflowID == "" || i.RejectionCode != "" || i.ManualReviewCode != "" {
            return ErrInvalid
        }
    case Rejected:
        if i.RejectionCode == "" || i.RunID != "" || i.WorkflowID != "" || i.ManualReviewCode != "" {
            return ErrInvalid
        }
    case ManualReview:
        if i.ManualReviewCode == "" || i.RunID != "" || i.WorkflowID != "" || i.RejectionCode != "" {
            return ErrInvalid
        }
    default:
        return ErrInvalid
    }
    return nil
}

func (i Intent) checkVersion(expected uint64) error {
    if i.Version != expected {
        return ErrStaleVersion
    }
    return nil
}

func (i Intent) checkLease(owner string, token uint64, now time.Time) error {
    if i.LeaseOwner != owner || i.FenceToken != token || owner == "" {
        return ErrStaleLease
    }
    if now.IsZero() || !now.Before(i.LeaseExpiresAt) {
        return ErrLeaseExpired
    }
    return nil
}

func (i Intent) clearLease() Intent {
    i.LeaseOwner = ""
    i.LeaseExpiresAt = time.Time{}
    return i
}

func (i Intent) manualReview(code string) Intent {
    i = i.clearLease()
    i.Status = ManualReview
    i.ManualReviewCode = code
    i.Version++
    return i
}

// ClaimDispatch is called after the RunIntent and Outbox event have been
// committed. The durable store must use a conditional version update.
func (i Intent) ClaimDispatch(expectedVersion uint64, owner string, now time.Time, ttl time.Duration) (Intent, error) {
    if err := i.Validate(); err != nil { return i, err }
    if err := i.checkVersion(expectedVersion); err != nil { return i, err }
    if i.Status != Pending { return i, ErrTransition }
    if strings.TrimSpace(owner) == "" || now.IsZero() || ttl <= 0 {
        return i, ErrInvalid
    }
    i.Status = Dispatching
    i.LeaseOwner = owner
    i.LeaseExpiresAt = now.Add(ttl)
    i.FenceToken++
    i.Version++
    return i, nil
}

// RecordDispatchOutcome accepts only the receipt held by the current lease.
// ACCEPTED means Runtime accepted the Run request; it does not mean the Run
// has started, completed, or succeeded.
func (i Intent) RecordDispatchOutcome(expectedVersion uint64, owner string, token uint64, now time.Time, outcome DispatchOutcome) (Intent, error) {
    if err := i.Validate(); err != nil { return i, err }
    if err := i.checkVersion(expectedVersion); err != nil { return i, err }
    if i.Status != Dispatching { return i, ErrTransition }
    if err := i.checkLease(owner, token, now); err != nil { return i, err }

    if outcome.RunIntentID != i.ID || outcome.RequestDigest != i.RequestDigest {
        return i.manualReview("RUNTIME_RECEIPT_MISMATCH"), nil
    }

    switch outcome.Kind {
    case DispatchAccepted:
        if outcome.RunID == "" || outcome.WorkflowID == "" || outcome.RejectionCode != "" {
            return i.manualReview("INVALID_RUNTIME_ACCEPTANCE"), nil
        }
        i.Status = Accepted
        i.RunID = outcome.RunID
        i.WorkflowID = outcome.WorkflowID
    case DispatchRejected:
        if outcome.RejectionCode == "" || outcome.RunID != "" || outcome.WorkflowID != "" {
            return i.manualReview("INVALID_RUNTIME_REJECTION"), nil
        }
        i.Status = Rejected
        i.RejectionCode = outcome.RejectionCode
    case DispatchAmbiguous:
        if outcome.RunID != "" || outcome.WorkflowID != "" || outcome.RejectionCode != "" {
            return i.manualReview("INVALID_AMBIGUOUS_RECEIPT"), nil
        }
        i.Status = Unknown
    default:
        return i, ErrInvalidOutcome
    }
    i = i.clearLease()
    i.Version++
    return i, nil
}

// ExpireLease fences a crashed or stalled dispatcher/reconciler. Its former
// worker can no longer commit because both version and fencing token change.
func (i Intent) ExpireLease(expectedVersion uint64, now time.Time) (Intent, error) {
    if err := i.Validate(); err != nil { return i, err }
    if err := i.checkVersion(expectedVersion); err != nil { return i, err }
    if i.Status != Dispatching && i.Status != Reconciling { return i, ErrTransition }
    if now.IsZero() || now.Before(i.LeaseExpiresAt) { return i, ErrLeaseActive }
    i = i.clearLease()
    i.Status = Unknown
    i.Version++
    return i, nil
}

func (i Intent) BeginReconciliation(expectedVersion uint64, owner string, now time.Time, ttl time.Duration) (Intent, error) {
    if err := i.Validate(); err != nil { return i, err }
    if err := i.checkVersion(expectedVersion); err != nil { return i, err }
    if i.Status != Unknown { return i, ErrTransition }
    if strings.TrimSpace(owner) == "" || now.IsZero() || ttl <= 0 { return i, ErrInvalid }
    i.Status = Reconciling
    i.LeaseOwner = owner
    i.LeaseExpiresAt = now.Add(ttl)
    i.FenceToken++
    i.Version++
    return i, nil
}

// ApplyReconciliationResult may retry only after Runtime's authoritative
// idempotency registry proves NOT_FOUND_FINAL. The same key and digest remain
// unchanged; no new RunIntent or operation identity is minted.
func (i Intent) ApplyReconciliationResult(expectedVersion uint64, owner string, token uint64, now time.Time, result ReconciliationResult) (Intent, error) {
    if err := i.Validate(); err != nil { return i, err }
    if err := i.checkVersion(expectedVersion); err != nil { return i, err }
    if i.Status != Reconciling { return i, ErrTransition }
    if err := i.checkLease(owner, token, now); err != nil { return i, err }

    if result.RunIntentID != i.ID || result.RequestDigest != i.RequestDigest {
        return i.manualReview("RUNTIME_RECONCILIATION_MISMATCH"), nil
    }

    switch result.Kind {
    case RuntimeFound:
        if result.RunID == "" || result.WorkflowID == "" || result.RejectionCode != "" {
            return i.manualReview("INVALID_RUNTIME_FOUND_RESULT"), nil
        }
        i.Status = Accepted
        i.RunID = result.RunID
        i.WorkflowID = result.WorkflowID
    case RuntimeNotFoundFinal:
        if result.RunID != "" || result.WorkflowID != "" || result.RejectionCode != "" {
            return i.manualReview("INVALID_RUNTIME_NOT_FOUND_RESULT"), nil
        }
        i.Status = Pending
    case RuntimeIndeterminate:
        if result.RunID != "" || result.WorkflowID != "" || result.RejectionCode != "" {
            return i.manualReview("INVALID_RUNTIME_INDETERMINATE_RESULT"), nil
        }
        i.Status = Unknown
    case RuntimeRejected:
        if result.RejectionCode == "" || result.RunID != "" || result.WorkflowID != "" {
            return i.manualReview("INVALID_RUNTIME_REJECTION"), nil
        }
        i.Status = Rejected
        i.RejectionCode = result.RejectionCode
    case RuntimeConflict:
        code := result.ReasonCode
        if code == "" { code = "RUNTIME_STATE_CONFLICT" }
        return i.manualReview(code), nil
    default:
        return i, ErrInvalidOutcome
    }
    i = i.clearLease()
    i.Version++
    return i, nil
}
