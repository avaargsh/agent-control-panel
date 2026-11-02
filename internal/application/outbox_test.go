package application

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/domain"
)

type memoryOutbox struct {
	mu     sync.Mutex
	events []domain.OutboxEvent
	acked  map[string]bool
	nacked map[string]time.Time
}

func (m *memoryOutbox) ClaimOutbox(_ context.Context, _ time.Time, _ time.Duration, limit int) ([]domain.OutboxEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	claimed := make([]domain.OutboxEvent, 0, limit)
	for _, event := range m.events {
		if len(claimed) == limit {
			break
		}
		if m.acked[event.ID] {
			continue
		}
		if _, retry := m.nacked[event.ID]; retry {
			continue
		}
		event.LeaseToken = "lease-" + event.ID
		event.Attempts++
		claimed = append(claimed, event)
	}
	return claimed, nil
}

func (m *memoryOutbox) AckOutbox(_ context.Context, id, token string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if token != "lease-"+id {
		return domain.ErrOutboxLeaseLost
	}
	m.acked[id] = true
	return nil
}

func (m *memoryOutbox) NackOutbox(_ context.Context, id, token, _ string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if token != "lease-"+id {
		return domain.ErrOutboxLeaseLost
	}
	m.nacked[id] = at
	return nil
}

type testOutboxHandler struct {
	err     error
	handled []string
}

func (h *testOutboxHandler) Handle(_ context.Context, event domain.OutboxEvent) error {
	h.handled = append(h.handled, event.ID)
	return h.err
}

func TestOutboxPublisherAcknowledgesSuccessfulDelivery(t *testing.T) {
	repo := &memoryOutbox{
		events: []domain.OutboxEvent{{ID: "evt-1", AggregateType: "Run", AggregateID: "run-1", AggregateVersion: 1, EventType: "RunCreated", Payload: []byte(`{"id":"run-1"}`), CreatedAt: time.Now()}},
		acked: map[string]bool{}, nacked: map[string]time.Time{},
	}
	handler := &testOutboxHandler{}
	publisher := NewOutboxPublisher(repo, handler)
	stats, err := publisher.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Claimed != 1 || stats.Published != 1 || stats.Retried != 0 || !repo.acked["evt-1"] {
		t.Fatalf("unexpected publish result: stats=%+v acked=%v", stats, repo.acked)
	}
}

func TestOutboxPublisherSchedulesRetryWhenHandlerFails(t *testing.T) {
	repo := &memoryOutbox{
		events: []domain.OutboxEvent{{ID: "evt-2", AggregateType: "Run", AggregateID: "run-2", AggregateVersion: 1, EventType: "RunCreated", Payload: []byte(`{"id":"run-2"}`), CreatedAt: time.Now()}},
		acked: map[string]bool{}, nacked: map[string]time.Time{},
	}
	handler := &testOutboxHandler{err: errors.New("temporary workflow outage")}
	publisher := NewOutboxPublisher(repo, handler)
	publisher.now = func() time.Time { return time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC) }
	stats, err := publisher.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Retried != 1 || stats.Published != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	want := publisher.now().Add(time.Second)
	if got := repo.nacked["evt-2"]; !got.Equal(want) {
		t.Fatalf("retry at %s, want %s", got, want)
	}
}

func TestOutboxPublisherBackoffCapsAtMaximum(t *testing.T) {
	publisher := NewOutboxPublisher(&memoryOutbox{}, &testOutboxHandler{})
	publisher.baseDelay = time.Second
	publisher.maxDelay = 8 * time.Second
	if got := publisher.retryDelay(10); got != 8*time.Second {
		t.Fatalf("got %s, want 8s", got)
	}
}
