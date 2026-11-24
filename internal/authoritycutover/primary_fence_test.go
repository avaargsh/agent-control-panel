package authoritycutover

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type fakePrimaryQueryer struct {
	identity primaryIdentity
	recovery bool
	err      error
	query    string
}

type fakePrimaryRow struct {
	identity primaryIdentity
	recovery bool
	err      error
}

func (q *fakePrimaryQueryer) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	q.query = query
	return fakePrimaryRow{identity: q.identity, recovery: q.recovery, err: q.err}
}

func (r fakePrimaryRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 5 {
		return errors.New("unexpected primary identity scan shape")
	}
	*dest[0].(*string) = r.identity.database
	*dest[1].(*string) = r.identity.address
	*dest[2].(*int) = r.identity.port
	*dest[3].(*time.Time) = r.identity.started
	*dest[4].(*bool) = r.recovery
	return nil
}

func TestPrimaryFenceAcceptsOnlyThePinnedWritablePrimary(t *testing.T) {
	started := time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC)
	expected := primaryIdentity{
		database: "acp",
		address:  "10.0.0.10",
		port:     5432,
		started:  started,
	}
	fence := &PrimaryFence{expected: &expected}

	tests := []struct {
		name     string
		queryer  *fakePrimaryQueryer
		wantPass bool
	}{
		{
			name: "same writable primary",
			queryer: &fakePrimaryQueryer{identity: expected},
			wantPass: true,
		},
		{
			name: "standby with same cluster endpoint",
			queryer: &fakePrimaryQueryer{identity: expected, recovery: true},
		},
		{
			name: "different backend address",
			queryer: &fakePrimaryQueryer{identity: primaryIdentity{
				database: "acp", address: "10.0.0.11", port: 5432, started: started,
			}},
		},
		{
			name: "different postmaster after failover",
			queryer: &fakePrimaryQueryer{identity: primaryIdentity{
				database: "acp", address: "10.0.0.10", port: 5432, started: started.Add(time.Minute),
			}},
		},
		{
			name: "different database",
			queryer: &fakePrimaryQueryer{identity: primaryIdentity{
				database: "other", address: "10.0.0.10", port: 5432, started: started,
			}},
		},
		{
			name: "identity probe error",
			queryer: &fakePrimaryQueryer{err: errors.New("connection lost")},
		},
		{
			name: "nil backend",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := fence.accept(context.Background(), test.queryer); got != test.wantPass {
				t.Fatalf("primary fence accept()=%v want %v", got, test.wantPass)
			}
		})
	}
}

func TestPrimaryFenceDoesNotPinBeforeInitializationButStillRejectsStandby(t *testing.T) {
	fence := NewPrimaryFence()
	primary := &fakePrimaryQueryer{identity: primaryIdentity{
		database: "acp", address: "10.0.0.10", port: 5432,
		started: time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC),
	}}
	if !fence.accept(context.Background(), primary) {
		t.Fatal("uninitialized fence should allow a writable primary for startup identity capture")
	}
	standby := &fakePrimaryQueryer{identity: primary.identity, recovery: true}
	if fence.accept(context.Background(), standby) {
		t.Fatal("uninitialized fence admitted a standby")
	}
}
