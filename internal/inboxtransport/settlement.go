// Package inboxtransport enforces the durable Inbox to broker settlement
// boundary without choosing a particular transport implementation.
package inboxtransport

import (
	"context"
	"errors"
	"fmt"

	"github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

var (
	ErrInvalidDelivery      = errors.New("Inbox delivery settlement is not configured")
	ErrInvalidReceiveResult = errors.New("invalid durable Inbox receive result")
)

// Receiver must not report a successful result until the Inbox event and any
// conflict evidence have committed to durable storage.
type Receiver interface {
	ReceiveInboxEvent(context.Context, string, postgres.Event) (postgres.InboxReceiveResult, error)
}

// Delivery is implemented by a concrete broker adapter. Ack must settle one
// delivery; DeadLetter must durably and idempotently transfer/reject it into
// a supervised dead-letter path before returning nil. A partial or failed
// settlement must return an error so at-least-once redelivery remains possible.
//
// No implementation of this interface is provided by the transport-neutral
// gate; a real broker ACK/DLQ fault-injection suite is still required.
type Delivery interface {
	Ack(context.Context) error
	DeadLetter(context.Context, string) error
}

const (
	ReasonEventIDConflict = "EVENT_ID_CONFLICT"
	ReasonQuarantined     = "INBOX_QUARANTINED"
)

// HandleDelivery never settles a broker delivery before durable Receive.
// Exact replays may ACK, while conflicts and quarantines require an explicit
// durable DLQ disposition. In particular, a changed redelivery of an APPLIED
// event has Conflict=true but Quarantined=false and must NOT ACK as normal.
//
// A settlement error is propagated: neither a failed broker ACK nor a failed
// DLQ transfer establishes that the source delivery was consumed. Replayed
// delivery identity and DLQ operations must be idempotent at the real adapter.
func HandleDelivery(ctx context.Context, receiver Receiver, delivery Delivery, consumer string, event postgres.Event) error {
	if receiver == nil || delivery == nil {
		return ErrInvalidDelivery
	}

	result, err := receiver.ReceiveInboxEvent(ctx, consumer, event)
	if err != nil {
		return fmt.Errorf("persist Inbox before broker settlement: %w", err)
	}
	// Every successful repository receipt describes exactly one durable
	// insertion or one durable duplicate; invented/contradictory receipts
	// must not allow any broker side effects.
	if result.Inserted == result.Duplicate || (result.Conflict && !result.Duplicate) {
		return ErrInvalidReceiveResult
	}

	if result.Conflict {
		if err := delivery.DeadLetter(ctx, ReasonEventIDConflict); err != nil {
			return fmt.Errorf("dead-letter conflicting Inbox delivery: %w", err)
		}
		return nil
	}
	if result.Quarantined {
		if err := delivery.DeadLetter(ctx, ReasonQuarantined); err != nil {
			return fmt.Errorf("dead-letter quarantined Inbox delivery: %w", err)
		}
		return nil
	}
	if err := delivery.Ack(ctx); err != nil {
		return fmt.Errorf("ACK committed Inbox delivery: %w", err)
	}
	return nil
}
