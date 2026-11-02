package domain

import (
	"encoding/json"
	"fmt"
	"time"
)

// OutboxEvent is an immutable domain event whose delivery is retried until it is
// acknowledged. Consumers must be idempotent by ID: delivery is at-least-once.
type OutboxEvent struct {
	ID               string          `json:"id"`
	AggregateType    string          `json:"aggregateType"`
	AggregateID      string          `json:"aggregateId"`
	AggregateVersion int64           `json:"aggregateVersion"`
	EventType        string          `json:"eventType"`
	Payload          json.RawMessage `json:"payload"`
	Attempts         int             `json:"attempts"`
	CreatedAt        time.Time       `json:"createdAt"`
	LeaseToken       string          `json:"-"`
}

func (e OutboxEvent) Validate() error {
	if e.ID == "" || e.AggregateType == "" || e.AggregateID == "" || e.EventType == "" {
		return fmt.Errorf("%w: outbox event identity and type are required", ErrInvalidInput)
	}
	if e.AggregateVersion < 1 || len(e.Payload) == 0 || !json.Valid(e.Payload) {
		return fmt.Errorf("%w: outbox event version and valid JSON payload are required", ErrInvalidInput)
	}
	if e.LeaseToken == "" {
		return fmt.Errorf("%w: outbox lease token is required", ErrInvalidInput)
	}
	return nil
}
