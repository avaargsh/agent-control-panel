package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

type RunStatus string

const (
	RunPending   RunStatus = "PENDING"
	RunRunning   RunStatus = "RUNNING"
	RunWaiting   RunStatus = "WAITING"
	RunSucceeded RunStatus = "SUCCEEDED"
	RunFailed    RunStatus = "FAILED"
	RunCancelled RunStatus = "CANCELLED"
)

func (s RunStatus) Terminal() bool {
	return s == RunSucceeded || s == RunFailed || s == RunCancelled
}

func (s RunStatus) Valid() bool {
	switch s {
	case RunPending, RunRunning, RunWaiting, RunSucceeded, RunFailed, RunCancelled:
		return true
	default:
		return false
	}
}

type Run struct {
	ID        string          `json:"id"`
	TenantID  string          `json:"tenantId"`
	AgentID   string          `json:"agentId"`
	ReleaseID string          `json:"releaseId"`
	SessionID string          `json:"sessionId"`
	Status    RunStatus       `json:"status"`
	Input     json.RawMessage `json:"input"`
	Version   int64           `json:"version"`
	Failure   string          `json:"failure,omitempty"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

func NewRun(id, tenantID, agentID, releaseID, sessionID string, input json.RawMessage, now time.Time) (Run, error) {
	for _, field := range []struct{ name, value string }{
		{"id", id}, {"tenantId", tenantID}, {"agentId", agentID},
		{"releaseId", releaseID}, {"sessionId", sessionID},
	} {
		if field.value == "" {
			return Run{}, fmt.Errorf("%w: %s is required", ErrInvalidInput, field.name)
		}
	}
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	if !json.Valid(input) {
		return Run{}, fmt.Errorf("%w: input must be valid JSON", ErrInvalidInput)
	}
	canonical := bytes.TrimSpace(input)
	return Run{
		ID: id, TenantID: tenantID, AgentID: agentID, ReleaseID: releaseID,
		SessionID: sessionID, Status: RunPending, Input: append(json.RawMessage(nil), canonical...),
		Version: 1, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func (r Run) Transition(to RunStatus, reason string, now time.Time) (Run, error) {
	if !to.Valid() {
		return Run{}, fmt.Errorf("%w: unknown target status %q", ErrInvalidTransition, to)
	}
	allowed := false
	switch r.Status {
	case RunPending:
		allowed = to == RunRunning || to == RunFailed || to == RunCancelled
	case RunRunning:
		allowed = to == RunWaiting || to == RunSucceeded || to == RunFailed || to == RunCancelled
	case RunWaiting:
		allowed = to == RunRunning || to == RunFailed || to == RunCancelled
	}
	if !allowed {
		return Run{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, r.Status, to)
	}
	if to == RunFailed && reason == "" {
		return Run{}, fmt.Errorf("%w: failure reason is required", ErrInvalidInput)
	}
	r.Status = to
	r.Failure = ""
	if to == RunFailed {
		r.Failure = reason
	}
	r.Version++
	r.UpdatedAt = now.UTC()
	return r, nil
}
