package main

import (
	"context"
	"errors"

	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/journal"
	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/lease"
)

var ErrBadQuery = errors.New("invalid sandbox inspect query")
var ErrUnverified = errors.New("sandbox status cannot be verified")

type Query struct {
	TenantID      string
	LeaseIntentID string
	SandboxUID    string
	CommandID     string
}

type LeaseView struct {
	LeaseIntentID    string `json:"lease_intent_id"`
	RunID            string `json:"run_id"`
	RuntimeAttemptID string `json:"runtime_attempt_id"`
	Generation       uint64 `json:"generation"`
	State            string `json:"state"`
}

type CommandView struct {
	SandboxUID       string `json:"sandbox_uid"`
	CommandID        string `json:"command_id"`
	RunID            string `json:"run_id"`
	RuntimeAttemptID string `json:"runtime_attempt_id"`
	Generation       uint64 `json:"generation"`
	State            string `json:"state"`
}

type Report struct {
	Schema             string       `json:"schema"`
	Source             string       `json:"source"`
	TenantID           string       `json:"tenant_id"`
	Lease              *LeaseView   `json:"lease,omitempty"`
	Command            *CommandView `json:"command,omitempty"`
	NextAction         string       `json:"next_action"`
	CanDispatch        bool         `json:"can_dispatch"`
	CanRetry           bool         `json:"can_retry"`
	CanDeclareSuccess  bool         `json:"can_declare_success"`
	CanDeclareReleased bool         `json:"can_declare_released"`
}

type LeaseReader interface {
	Get(context.Context, string, string) (lease.Record, error)
}
type CommandReader interface {
	Get(context.Context, string, string, string) (journal.Record, error)
}

func inspect(ctx context.Context, query Query, leases LeaseReader, commands CommandReader) (Report, error) {
	return Report{}, ErrUnverified
}
