package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/internal/identity"
	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/journal"
	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/lease"
)

type fakeLease struct {
	record lease.Record
	err    error
	calls  int
}

func (f *fakeLease) Get(_ context.Context, _, _ string) (lease.Record, error) {
	f.calls++
	return f.record, f.err
}

type fakeCommand struct {
	record journal.Record
	err    error
	calls  int
}

func (f *fakeCommand) Get(_ context.Context, _, _, _ string) (journal.Record, error) {
	f.calls++
	return f.record, f.err
}

func exampleReaders() (*fakeLease, *fakeCommand, Query) {
	q := Query{TenantID: "tenant-a", LeaseIntentID: "lease-1", SandboxUID: "sandbox-1", CommandID: "command-1"}
	l := &fakeLease{record: lease.Record{Intent: lease.Intent{
		TenantID: q.TenantID, LeaseIntentID: q.LeaseIntentID, RunID: "run-1", RuntimeAttemptID: "runtime-attempt-1",
		RequestDigest: "sha256:" + strings.Repeat("a", 64),
	}, Generation: 1, State: lease.WaitingForPermit}}
	c := &fakeCommand{record: journal.Record{Identity: identity.Intent{
		TenantID: q.TenantID, SandboxUID: q.SandboxUID, CommandID: q.CommandID,
		RunID: "run-1", RuntimeAttemptID: "runtime-attempt-1", RequestDigest: "sha256:" + strings.Repeat("b", 64),
	}, Generation: 1, State: journal.PermitUnavailable}}
	return l, c, q
}

func TestInspectShowsTwoVerifiedLocalSnapshotsButNeverAuthorizesEffects(t *testing.T) {
	l, c, q := exampleReaders()
	report, err := inspect(context.Background(), q, l, c)
	if err != nil {
		t.Fatal(err)
	}
	if l.calls != 1 || c.calls != 1 || report.Lease == nil || report.Command == nil ||
		report.Lease.State != lease.WaitingForPermit || report.Command.State != journal.PermitUnavailable ||
		report.Source != "UNATTESTED_DB_SNAPSHOT" || report.NextAction != "HOLD" ||
		report.CanDispatch || report.CanRetry || report.CanDeclareSuccess || report.CanDeclareReleased {
		t.Fatalf("unsafe or misleading inspection: %+v", report)
	}
}

func TestInspectCancelledIntentMustNotClaimProviderRelease(t *testing.T) {
	l, c, q := exampleReaders()
	l.record.State = lease.CancelledBeforeProvision
	l.record.Generation = 2
	report, err := inspect(context.Background(), q, l, c)
	if err != nil || report.NextAction != "STOP_NO_PROVIDER_ACTION" || report.CanDeclareReleased ||
		report.CanDispatch || report.CanRetry || report.CanDeclareSuccess {
		t.Fatalf("cancelled intent promoted to resource release: %+v %v", report, err)
	}
}

func TestInspectOnlyLeaseOrOnlyJournal(t *testing.T) {
	l, c, q := exampleReaders()
	q.CommandID, q.SandboxUID = "", ""
	report, err := inspect(context.Background(), q, l, nil)
	if err != nil || report.Lease == nil || report.Command != nil || report.NextAction != "HOLD" {
		t.Fatalf("lease-only fails: %+v %v", report, err)
	}
	q.LeaseIntentID, q.SandboxUID, q.CommandID = "", "sandbox-1", "command-1"
	report, err = inspect(context.Background(), q, nil, c)
	if err != nil || report.Lease != nil || report.Command == nil || report.NextAction != "HOLD" {
		t.Fatalf("journal-only fails: %+v %v", report, err)
	}
}

func TestInspectFailsClosedOnMismatchedAuthorityRecords(t *testing.T) {
	tests := []struct {
		name   string
		change func(*fakeLease, *fakeCommand)
	}{
		{"wrong lease tenant", func(l *fakeLease, _ *fakeCommand) { l.record.Intent.TenantID = "other" }},
		{"wrong journal tenant", func(_ *fakeLease, c *fakeCommand) { c.record.Identity.TenantID = "other" }},
		{"different run", func(_ *fakeLease, c *fakeCommand) { c.record.Identity.RunID = "run-2" }},
		{"different Runtime attempt", func(_ *fakeLease, c *fakeCommand) { c.record.Identity.RuntimeAttemptID = "attempt-2" }},
		{"wrong sandbox UID", func(_ *fakeLease, c *fakeCommand) { c.record.Identity.SandboxUID = "sandbox-other" }},
		{"wrong command ID", func(_ *fakeLease, c *fakeCommand) { c.record.Identity.CommandID = "command-other" }},
		{"stale lease generation", func(l *fakeLease, _ *fakeCommand) { l.record.Generation = 0 }},
		{"fake provision", func(l *fakeLease, _ *fakeCommand) { l.record.State = "PROVISIONED" }},
		{"fake executed command", func(_ *fakeLease, c *fakeCommand) { c.record.State = "EXITED" }},
		{"wrong journal generation", func(_ *fakeLease, c *fakeCommand) { c.record.Generation = 2 }},
		{"missing permit record", func(_ *fakeLease, c *fakeCommand) { c.err = journal.ErrNotFound }},
		{"missing lease record", func(l *fakeLease, _ *fakeCommand) { l.err = lease.ErrNotFound }},
		{"journal IO failure", func(_ *fakeLease, c *fakeCommand) { c.err = errors.New("database unavailable") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, c, q := exampleReaders()
			tt.change(l, c)
			got, err := inspect(context.Background(), q, l, c)
			if !errors.Is(err, ErrUnverified) || got.CanDispatch || got.CanRetry ||
				got.CanDeclareSuccess || got.CanDeclareReleased {
				t.Fatalf("forged, missing or unavailable record accepted: %+v %v", got, err)
			}
		})
	}
}

func TestInspectRejectsMalformedOrIncompleteQueriesBeforeDBCall(t *testing.T) {
	invalid := []Query{
		{}, {TenantID: "tenant-a"}, {TenantID: "tenant-a", SandboxUID: "sandbox-1"},
		{TenantID: "tenant-a", CommandID: "command-1"},
		{TenantID: "tenant a", LeaseIntentID: "lease-1"},
		{TenantID: "tenant-a", LeaseIntentID: "lease\n1"},
	}
	for _, q := range invalid {
		l, c, _ := exampleReaders()
		_, err := inspect(context.Background(), q, l, c)
		if !errors.Is(err, ErrBadQuery) || l.calls != 0 || c.calls != 0 {
			t.Fatalf("invalid query reached read: %+v %v", q, err)
		}
	}
}
