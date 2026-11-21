package main

import (
	"context"
	"errors"
	"regexp"

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

// Queries are developer-tool inputs, not authority. The CLI never issues
// permissions or writes records; it only displays untrusted local snapshots.
var opaqueReference = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")

func validQuery(q Query) bool {
	if !opaqueReference.MatchString(q.TenantID) {
		return false
	}
	if q.LeaseIntentID == "" && (q.SandboxUID == "" || q.CommandID == "") {
		return false
	}
	if (q.SandboxUID == "") != (q.CommandID == "") {
		return false
	}
	for _, ref := range []string{q.LeaseIntentID, q.SandboxUID, q.CommandID} {
		if ref != "" && !opaqueReference.MatchString(ref) {
			return false
		}
	}
	return true
}

// inspect combines existing non-effectful records only when their immutable
// Runtime Run and Runtime Attempt references agree. It does NOT authenticate
// the database source or prove a provider action occurred (or did not occur).
func inspect(ctx context.Context, q Query, leases LeaseReader, commands CommandReader) (Report, error) {
	if !validQuery(q) {
		return Report{}, ErrBadQuery
	}
	out := Report{
		Schema: "sandboxctl.inspect.v0", Source: "UNATTESTED_DB_SNAPSHOT",
		TenantID: q.TenantID, NextAction: "HOLD",
	}
	if q.LeaseIntentID != "" {
		if leases == nil {
			return Report{}, ErrUnverified
		}
		rec, err := leases.Get(ctx, q.TenantID, q.LeaseIntentID)
		if err != nil || rec.Intent.TenantID != q.TenantID ||
			rec.Intent.LeaseIntentID != q.LeaseIntentID ||
			rec.Intent.Validate() != nil ||
			!((rec.Generation == 1 && rec.State == lease.WaitingForPermit) ||
				(rec.Generation == 2 && rec.State == lease.CancelledBeforeProvision)) {
			return Report{}, ErrUnverified
		}
		out.Lease = &LeaseView{
			LeaseIntentID: rec.Intent.LeaseIntentID, RunID: rec.Intent.RunID,
			RuntimeAttemptID: rec.Intent.RuntimeAttemptID,
			Generation:       rec.Generation, State: rec.State,
		}
		if rec.State == lease.CancelledBeforeProvision {
			out.NextAction = "STOP_NO_PROVIDER_ACTION"
		}
	}
	if q.CommandID != "" {
		if commands == nil {
			return Report{}, ErrUnverified
		}
		rec, err := commands.Get(ctx, q.TenantID, q.SandboxUID, q.CommandID)
		if err != nil || rec.Identity.TenantID != q.TenantID ||
			rec.Identity.SandboxUID != q.SandboxUID || rec.Identity.CommandID != q.CommandID ||
			rec.Identity.Validate() != nil || rec.Generation != 1 ||
			rec.State != journal.PermitUnavailable {
			return Report{}, ErrUnverified
		}
		if out.Lease != nil && (out.Lease.RunID != rec.Identity.RunID ||
			out.Lease.RuntimeAttemptID != rec.Identity.RuntimeAttemptID) {
			return Report{}, ErrUnverified
		}
		out.Command = &CommandView{
			SandboxUID: rec.Identity.SandboxUID, CommandID: rec.Identity.CommandID,
			RunID: rec.Identity.RunID, RuntimeAttemptID: rec.Identity.RuntimeAttemptID,
			Generation: rec.Generation, State: rec.State,
		}
	}
	return out, nil
}
