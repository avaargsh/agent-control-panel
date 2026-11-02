package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/application"
	"github.com/avaargsh/agent-control-panel/internal/domain"
)

type testRepository struct {
	runs map[string]domain.Run
	idem map[string]struct{ hash, id string }
}

func newTestRepository() *testRepository {
	return &testRepository{runs: map[string]domain.Run{}, idem: map[string]struct{ hash, id string }{}}
}
func (m *testRepository) CreateRun(_ context.Context, run domain.Run, key, hash string) (domain.Run, bool, error) {
	scope := run.TenantID + ":" + key
	if old, ok := m.idem[scope]; ok {
		if old.hash != hash {
			return domain.Run{}, false, domain.ErrIdempotencyConflict
		}
		return m.runs[old.id], false, nil
	}
	m.runs[run.ID] = run
	m.idem[scope] = struct{ hash, id string }{hash, run.ID}
	return run, true, nil
}
func (m *testRepository) GetRun(_ context.Context, tenant, id string) (domain.Run, error) {
	r, ok := m.runs[id]
	if !ok || r.TenantID != tenant {
		return domain.Run{}, domain.ErrNotFound
	}
	return r, nil
}
func (m *testRepository) TransitionRun(_ context.Context, tenant, id string, version int64, target domain.RunStatus, reason string, at time.Time) (domain.Run, error) {
	r, ok := m.runs[id]
	if !ok || r.TenantID != tenant {
		return domain.Run{}, domain.ErrNotFound
	}
	if r.Version != version {
		return domain.Run{}, domain.ErrVersionConflict
	}
	next, err := r.Transition(target, reason, at)
	if err != nil {
		return domain.Run{}, err
	}
	m.runs[id] = next
	return next, nil
}

func TestCreateRunEndpointReturnsCreatedThenIdempotentReplay(t *testing.T) {
	handler := New(application.NewRunService(newTestRepository()))
	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/runs", strings.NewReader(`{"agentId":"agent-1","releaseId":"release-1","input":{"task":"summarize"}}`))
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req.Header.Set("Idempotency-Key", "intent-1")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	first := request()
	if first.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", first.Code, first.Body.String())
	}
	second := request()
	if second.Code != http.StatusOK {
		t.Fatalf("expected replay 200, got %d: %s", second.Code, second.Body.String())
	}
	var a, b domain.Run
	if err := json.Unmarshal(first.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID || a.SessionID != b.SessionID {
		t.Fatalf("idempotent replay changed resource identity: first=%+v second=%+v", a, b)
	}
}

func TestCreateRunEndpointRejectsUnknownFields(t *testing.T) {
	handler := New(application.NewRunService(newTestRepository()))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runs", strings.NewReader(`{"agentId":"a","releaseId":"r","unexpected":true}`))
	req.Header.Set("X-Tenant-ID", "t")
	req.Header.Set("Idempotency-Key", "k")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetRunDoesNotCrossTenantBoundary(t *testing.T) {
	repo := newTestRepository()
	svc := application.NewRunService(repo)
	run, _, err := svc.Create(context.Background(), application.CreateRunCommand{TenantID: "tenant-a", AgentID: "agent-a", ReleaseID: "release-a", IdempotencyKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	handler := New(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs/"+run.ID, nil)
	req.Header.Set("X-Tenant-ID", "tenant-b")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected tenant-scoped 404, got %d: %s", w.Code, w.Body.String())
	}
}
