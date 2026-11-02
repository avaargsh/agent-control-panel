package application

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/domain"
)

type memoryRepository struct {
	mu          sync.Mutex
	runs        map[string]domain.Run
	idempotency map[string]struct{ hash, runID string }
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{runs: map[string]domain.Run{}, idempotency: map[string]struct{ hash, runID string }{}}
}

func (m *memoryRepository) CreateRun(_ context.Context, run domain.Run, key, hash string) (domain.Run, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	scope := run.TenantID + ":POST:/runs:" + key
	if prior, ok := m.idempotency[scope]; ok {
		if prior.hash != hash {
			return domain.Run{}, false, domain.ErrIdempotencyConflict
		}
		return m.runs[prior.runID], false, nil
	}
	m.runs[run.ID] = run
	m.idempotency[scope] = struct{ hash, runID string }{hash, run.ID}
	return run, true, nil
}

func (m *memoryRepository) GetRun(_ context.Context, tenantID, runID string) (domain.Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok || run.TenantID != tenantID {
		return domain.Run{}, domain.ErrNotFound
	}
	return run, nil
}

func (m *memoryRepository) TransitionRun(_ context.Context, tenantID, runID string, expected int64, target domain.RunStatus, reason string, at time.Time) (domain.Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok || run.TenantID != tenantID {
		return domain.Run{}, domain.ErrNotFound
	}
	if run.Version != expected {
		return domain.Run{}, domain.ErrVersionConflict
	}
	updated, err := run.Transition(target, reason, at)
	if err != nil {
		return domain.Run{}, err
	}
	m.runs[runID] = updated
	return updated, nil
}

func TestCreateRunHonoursIdempotencyAcrossRetries(t *testing.T) {
	repo := newMemoryRepository()
	svc := NewRunService(repo)
	cmd := CreateRunCommand{TenantID: "tenant-1", AgentID: "agent-1", ReleaseID: "release-1", Input: json.RawMessage(`{"task":"test"}`), IdempotencyKey: "request-1"}
	first, created, err := svc.Create(context.Background(), cmd)
	if err != nil || !created {
		t.Fatalf("first create: created=%v err=%v", created, err)
	}
	second, created, err := svc.Create(context.Background(), cmd)
	if err != nil || created {
		t.Fatalf("retry: created=%v err=%v", created, err)
	}
	if first.ID != second.ID || first.SessionID != second.SessionID {
		t.Fatalf("retry created different logical resource: first=%+v second=%+v", first, second)
	}
}

func TestCreateRunRejectsIdempotencyKeyWithDifferentPayload(t *testing.T) {
	svc := NewRunService(newMemoryRepository())
	cmd := CreateRunCommand{TenantID: "tenant-1", AgentID: "agent-1", ReleaseID: "release-1", Input: json.RawMessage(`{"task":"one"}`), IdempotencyKey: "same-key"}
	if _, _, err := svc.Create(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	cmd.Input = json.RawMessage(`{"task":"two"}`)
	_, _, err := svc.Create(context.Background(), cmd)
	if !errors.Is(err, domain.ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}

func TestCreateRunCanonicalizesJSONForIdempotencyHash(t *testing.T) {
	a := CreateRunCommand{TenantID: "t", AgentID: "a", ReleaseID: "r", Input: json.RawMessage(`{"a":1,"b":2}`)}
	b := a
	b.Input = json.RawMessage(` { "b": 2, "a": 1 } `)
	ha, err := hashCreateCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := hashCreateCommand(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("canonical equivalent JSON produced different hashes: %s != %s", ha, hb)
	}
}

func TestTransitionUsesOptimisticVersion(t *testing.T) {
	repo := newMemoryRepository()
	svc := NewRunService(repo)
	run, _, err := svc.Create(context.Background(), CreateRunCommand{TenantID: "t", AgentID: "a", ReleaseID: "r", IdempotencyKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := svc.Transition(context.Background(), "t", run.ID, run.Version, domain.RunRunning, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Transition(context.Background(), "t", run.ID, run.Version, domain.RunSucceeded, ""); !errors.Is(err, domain.ErrVersionConflict) {
		t.Fatalf("expected version conflict, got %v", err)
	}
	if updated.Version != 2 {
		t.Fatalf("expected version 2, got %d", updated.Version)
	}
}

func TestConcurrentCreateRunRetriesProduceOneCanonicalRun(t *testing.T) {
	repo := newMemoryRepository()
	svc := NewRunService(repo)
	cmd := CreateRunCommand{TenantID: "tenant-1", AgentID: "agent-1", ReleaseID: "release-1", Input: json.RawMessage(`{"task":"fanout"}`), IdempotencyKey: "one-intent"}
	const callers = 16
	ids := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run, _, err := svc.Create(context.Background(), cmd)
			if err != nil {
				errs <- err
				return
			}
			ids <- run.ID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent create failed: %v", err)
	}
	canonical := ""
	for id := range ids {
		if canonical == "" {
			canonical = id
			continue
		}
		if id != canonical {
			t.Fatalf("concurrent retries produced multiple Runs: %s and %s", canonical, id)
		}
	}
	if len(repo.runs) != 1 {
		t.Fatalf("expected exactly one persisted Run, got %d", len(repo.runs))
	}
}
