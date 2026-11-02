package domain

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func newTestRun(t *testing.T) Run {
	t.Helper()
	r, err := NewRun("run-1", "tenant-1", "agent-1", "release-1", "session-1", json.RawMessage(`{"task":"inspect"}`), time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRunAllowsExpectedLifecycle(t *testing.T) {
	r := newTestRun(t)
	for _, next := range []RunStatus{RunRunning, RunWaiting, RunRunning, RunSucceeded} {
		var err error
		r, err = r.Transition(next, "", time.Now())
		if err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
	if r.Status != RunSucceeded || r.Version != 5 {
		t.Fatalf("unexpected final run: %+v", r)
	}
}

func TestRunRejectsTerminalTransition(t *testing.T) {
	r := newTestRun(t)
	r, _ = r.Transition(RunRunning, "", time.Now())
	r, _ = r.Transition(RunSucceeded, "", time.Now())
	_, err := r.Transition(RunRunning, "", time.Now())
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}
}

func TestRunFailureRequiresReason(t *testing.T) {
	r := newTestRun(t)
	r, _ = r.Transition(RunRunning, "", time.Now())
	_, err := r.Transition(RunFailed, "", time.Now())
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestNewRunRejectsInvalidJSON(t *testing.T) {
	_, err := NewRun("run-1", "tenant-1", "agent-1", "release-1", "session-1", json.RawMessage(`{`), time.Now())
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}
