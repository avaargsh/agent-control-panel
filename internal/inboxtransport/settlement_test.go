package inboxtransport

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

type receiveFixture struct {
	result    postgres.InboxReceiveResult
	err       error
	calls     int
	committed bool
}

func (f *receiveFixture) ReceiveInboxEvent(_ context.Context, consumer string, event postgres.Event) (postgres.InboxReceiveResult, error) {
	f.calls++
	if consumer != "billing-consumer" || event.ID != "00000000-0000-4000-8000-000000000101" {
		return postgres.InboxReceiveResult{}, errors.New("incorrect delivery identity")
	}
	if f.err == nil {
		f.committed = true
	}
	return f.result, f.err
}

type settlementFixture struct {
	receiver *receiveFixture
	calls    []string
	ackErr   error
	dlqErr   error
}

func (f *settlementFixture) Ack(_ context.Context) error {
	if !f.receiver.committed {
		return errors.New("ACK attempted before durable receive")
	}
	f.calls = append(f.calls, "ACK")
	return f.ackErr
}

func (f *settlementFixture) DeadLetter(_ context.Context, reason string) error {
	if !f.receiver.committed {
		return errors.New("DLQ attempted before durable receive")
	}
	f.calls = append(f.calls, "DLQ:"+reason)
	return f.dlqErr
}

func TestHandleDeliveryFailClosedSettlement(t *testing.T) {
	databaseFailure := errors.New("database commit unavailable")
	ackFailure := errors.New("broker ACK failed")
	dlqFailure := errors.New("durable DLQ transfer failed")
	tests := []struct {
		name       string
		result     postgres.InboxReceiveResult
		receiveErr error
		ackErr     error
		dlqErr     error
		wantCalls  []string
		wantErr    error
	}{
		{"new durable intake", postgres.InboxReceiveResult{Inserted: true}, nil, nil, nil, []string{"ACK"}, nil},
		{"exact redelivery", postgres.InboxReceiveResult{Duplicate: true}, nil, nil, nil, []string{"ACK"}, nil},
		{"event ID conflict after original applied", postgres.InboxReceiveResult{Duplicate: true, Conflict: true}, nil, nil, nil, []string{"DLQ:EVENT_ID_CONFLICT"}, nil},
		{"event ID conflict before apply", postgres.InboxReceiveResult{Duplicate: true, Quarantined: true, Conflict: true}, nil, nil, nil, []string{"DLQ:EVENT_ID_CONFLICT"}, nil},
		{"aggregate version conflict", postgres.InboxReceiveResult{Inserted: true, Quarantined: true}, nil, nil, nil, []string{"DLQ:INBOX_QUARANTINED"}, nil},
		{"previously quarantined exact redelivery", postgres.InboxReceiveResult{Duplicate: true, Quarantined: true}, nil, nil, nil, []string{"DLQ:INBOX_QUARANTINED"}, nil},
		{"database failure never settles", postgres.InboxReceiveResult{}, databaseFailure, nil, nil, nil, databaseFailure},
		{"invalid empty repository receipt", postgres.InboxReceiveResult{}, nil, nil, nil, nil, ErrInvalidReceiveResult},
		{"invalid contradictory repository receipt", postgres.InboxReceiveResult{Inserted: true, Duplicate: true}, nil, nil, nil, nil, ErrInvalidReceiveResult},
		{"ACK failure leaves delivery unsettled", postgres.InboxReceiveResult{Inserted: true}, nil, ackFailure, nil, []string{"ACK"}, ackFailure},
		{"DLQ failure leaves delivery unsettled", postgres.InboxReceiveResult{Duplicate: true, Conflict: true}, nil, nil, dlqFailure, []string{"DLQ:EVENT_ID_CONFLICT"}, dlqFailure},
	}
	event := postgres.Event{ID: "00000000-0000-4000-8000-000000000101"}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			receiver := &receiveFixture{result: tc.result, err: tc.receiveErr}
			delivery := &settlementFixture{receiver: receiver, ackErr: tc.ackErr, dlqErr: tc.dlqErr}
			err := HandleDelivery(context.Background(), receiver, delivery, "billing-consumer", event)
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("unexpected settlement error: %v", err)
			}
			if !reflect.DeepEqual(delivery.calls, tc.wantCalls) {
				t.Fatalf("settlement calls=%v, want=%v", delivery.calls, tc.wantCalls)
			}
			if receiver.calls != 1 {
				t.Fatalf("receiver invoked %d times; want one durable intake", receiver.calls)
			}
		})
	}
}

func TestHandleDeliveryRejectsMissingDependenciesWithoutSettlement(t *testing.T) {
	receiver := &receiveFixture{result: postgres.InboxReceiveResult{Inserted: true}}
	delivery := &settlementFixture{receiver: receiver}
	event := postgres.Event{ID: "00000000-0000-4000-8000-000000000101"}
	if err := HandleDelivery(context.Background(), nil, delivery, "billing-consumer", event); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("missing receiver accepted: %v", err)
	}
	if err := HandleDelivery(context.Background(), receiver, nil, "billing-consumer", event); !errors.Is(err, ErrInvalidDelivery) {
		t.Fatalf("missing delivery accepted: %v", err)
	}
	if receiver.calls != 0 || len(delivery.calls) != 0 {
		t.Fatalf("invalid handler performed side effects: received=%d settlement=%v", receiver.calls, delivery.calls)
	}
}
