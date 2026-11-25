package authoritycutover

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrPrimaryIdentityUnavailable = errors.New("PostgreSQL primary identity unavailable")

type primaryIdentity struct {
	database string
	address  string
	port     int
	started  time.Time
}

func (i primaryIdentity) equal(other primaryIdentity) bool {
	return i.database == other.database &&
		i.address == other.address &&
		i.port == other.port &&
		i.started.Equal(other.started)
}

type primaryIdentityQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// PrimaryFence pins every acquired pool backend to the same writable
// PostgreSQL postmaster observed at startup. A failover or endpoint reroute
// deliberately requires process restart and fresh verification; it never
// silently moves an active admission barrier to a different server.
type PrimaryFence struct {
	mu       sync.RWMutex
	expected *primaryIdentity
}

func NewPrimaryFence() *PrimaryFence {
	return &PrimaryFence{}
}

// BeforeAcquire is installed on both the authority read pool and the
// independent cutover observer pool. pgxpool invokes it for every acquired
// backend, including connections created after a network failure.
func (f *PrimaryFence) BeforeAcquire(ctx context.Context, conn *pgx.Conn) bool {
	return f.accept(ctx, conn)
}

func (f *PrimaryFence) accept(ctx context.Context, queryer primaryIdentityQueryer) bool {
	if f == nil || queryer == nil || ctx.Err() != nil {
		return false
	}
	got, err := readPrimaryIdentity(ctx, queryer)
	if err != nil {
		return false
	}
	f.mu.RLock()
	expected := f.expected
	if expected == nil {
		f.mu.RUnlock()
		return true
	}
	matches := got.equal(*expected)
	f.mu.RUnlock()
	return matches
}

// Initialize compares one actual backend from each pool and pins the
// resulting identity. The pool callbacks reject standby connections even
// before this comparison; a mismatch prevents service startup.
func (f *PrimaryFence) Initialize(ctx context.Context, authority, cutover *pgxpool.Pool) error {
	if f == nil || authority == nil || cutover == nil {
		return ErrPrimaryIdentityUnavailable
	}
	authorityIdentity, err := readPoolPrimaryIdentity(ctx, authority)
	if err != nil {
		return fmt.Errorf("%w: authority backend: %v", ErrPrimaryIdentityUnavailable, err)
	}
	cutoverIdentity, err := readPoolPrimaryIdentity(ctx, cutover)
	if err != nil {
		return fmt.Errorf("%w: cutover backend: %v", ErrPrimaryIdentityUnavailable, err)
	}
	if !authorityIdentity.equal(cutoverIdentity) {
		return ErrPrimaryIdentityUnavailable
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.expected != nil && !f.expected.equal(authorityIdentity) {
		return ErrPrimaryIdentityUnavailable
	}
	pinned := authorityIdentity
	f.expected = &pinned
	return nil
}

func readPoolPrimaryIdentity(ctx context.Context, pool *pgxpool.Pool) (primaryIdentity, error) {
	if pool == nil {
		return primaryIdentity{}, ErrPrimaryIdentityUnavailable
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return primaryIdentity{}, err
	}
	defer conn.Release()
	return readPrimaryIdentity(ctx, conn.Conn())
}

func readPrimaryIdentity(ctx context.Context, queryer primaryIdentityQueryer) (primaryIdentity, error) {
	if queryer == nil || ctx.Err() != nil {
		return primaryIdentity{}, ErrPrimaryIdentityUnavailable
	}
	var got primaryIdentity
	var inRecovery bool
	err := queryer.QueryRow(ctx, `SELECT current_database(),
		COALESCE(inet_server_addr()::text, ''), COALESCE(inet_server_port(), 0),
		pg_postmaster_start_time(), pg_is_in_recovery()`).Scan(
		&got.database, &got.address, &got.port, &got.started, &inRecovery,
	)
	if err != nil {
		return primaryIdentity{}, err
	}
	if inRecovery {
		return primaryIdentity{}, ErrPrimaryIdentityUnavailable
	}
	return got, nil
}
