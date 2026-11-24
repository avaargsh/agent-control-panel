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

// admissionBarrierLockKey is a stable, database-scoped advisory lock key.
// Every serving replica and the trusted cutover coordinator must use this
// exact key against the same PostgreSQL primary.
const (
	admissionBarrierLockKey int64 = 0x4143504355544f56
	// DDL and admission use distinct keys: the coordinator may hold the
	// exclusive admission lock while a separate operator LOGIN performs DCL.
	// The event trigger serializes only against active request DDL leases.
	ddlChangeBarrierLockKey int64 = 0x41435044444c464e
)

var (
	ErrBarrierUnavailable = errors.New("authority admission barrier unavailable")
	ErrAdmissionClosed    = errors.New("authority admission closed")
)

// RequestLease is held for the complete HTTP handler lifetime, through the
// final response flush. Release must be called exactly once.
type RequestLease interface {
	Release() error
}

// RequestGate is implemented by a shared, durable admission barrier.
type RequestGate interface {
	Acquire(context.Context) (RequestLease, error)
}

// PostgresBarrier coordinates serving replicas through PostgreSQL advisory
// locks and the durable cutover state row. It is opt-in and does not replace
// the normal authority role guard. Observer instances admit requests; the
// coordinator instance obtains the exclusive drain lock.
type PostgresBarrier struct {
	pool  *pgxpool.Pool
	login string
	mode  RoleMode
}

func NewPostgresBarrier(pool *pgxpool.Pool, login string, mode RoleMode) *PostgresBarrier {
	return &PostgresBarrier{pool: pool, login: login, mode: mode}
}

// VerifyDDLBarrier confirms that the database-local ddl_command_start trigger
// is enabled and bound to the DDL lock key used by request leases. A missing,
// disabled, or replaced trigger must fail closed before any authority read or
// cutover operation is admitted.
func VerifyDDLBarrier(ctx context.Context, conn *pgx.Conn) error {
	if conn == nil || ctx.Err() != nil {
		return ErrBarrierUnavailable
	}
	const probe = `
SELECT EXISTS (
 SELECT 1
 FROM pg_catalog.pg_event_trigger e
 JOIN pg_catalog.pg_proc f ON f.oid=e.evtfoid
 JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace
 JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=f.proowner
 WHERE e.evtname='acp_authority_catalog_change_fence'
   AND e.evtevent='ddl_command_start'
   AND e.evtenabled IN ('O','A')
   AND e.evttags IS NULL
   AND n.nspname='public'
   AND f.proname='acp_authority_catalog_change_fence'
   AND f.prorettype='pg_catalog.event_trigger'::regtype
   AND NOT f.prosecdef
   AND f.proconfig @> ARRAY['search_path=pg_catalog']::text[]
   AND f.proowner=e.evtowner
   AND owner_role.rolsuper
   AND position('pg_advisory_xact_lock(4702690690038777422)' in f.prosrc)>0
)`
	var valid bool
	if err := conn.QueryRow(ctx, probe).Scan(&valid); err != nil || !valid || ctx.Err() != nil {
		return ErrBarrierUnavailable
	}
	return nil
}

// Acquire verifies an independently authenticated Observer LOGIN, takes a
// non-blocking shared session lock, and checks the durable ledger is OPEN.
// The returned lease keeps that same backend's lock until the HTTP response
// has been flushed and the caller releases it. A DRAINING/CLOSED/VERIFYING
// state or an active exclusive cutover rejects admission.
func (b *PostgresBarrier) Acquire(ctx context.Context) (RequestLease, error) {
	if b == nil || b.pool == nil || b.login == "" || b.mode != ObserverRole {
		return nil, ErrBarrierUnavailable
	}
	conn, err := b.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: acquire observer backend: %w", ErrBarrierUnavailable, err)
	}
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_catalog.pg_try_advisory_lock_shared($1)", admissionBarrierLockKey).Scan(&locked); err != nil {
		discardBarrierBackend(conn)
		return nil, fmt.Errorf("%w: shared lock: %w", ErrBarrierUnavailable, err)
	}
	if !locked {
		conn.Release()
		return nil, ErrAdmissionClosed
	}
	// Acquire a second shared session lock for local DDL/GRANT/REVOKE. It is
	// intentionally distinct from the coordinator admission key so a
	// separate DCL operator can run while the coordinator holds admission
	// CLOSED after draining all requests.
	var ddlLocked bool
	if err := conn.QueryRow(ctx, "SELECT pg_catalog.pg_try_advisory_lock_shared($1)", ddlChangeBarrierLockKey).Scan(&ddlLocked); err != nil {
		discardBarrierBackend(conn)
		return nil, fmt.Errorf("%w: acquire DDL shared lock: %w", ErrBarrierUnavailable, err)
	}
	if !ddlLocked {
		if releaseErr := releaseBarrierBackend(conn, true); releaseErr != nil {
			return nil, fmt.Errorf("%w: DDL change in progress; admission lock release: %w", ErrBarrierUnavailable, releaseErr)
		}
		return nil, ErrBarrierUnavailable
	}
	releaseRequest := func(cause error, phase string) (RequestLease, error) {
		if releaseErr := releaseRequestBackend(conn); releaseErr != nil {
			return nil, fmt.Errorf("%w: %s: %v; request lease release: %w", ErrBarrierUnavailable, phase, cause, releaseErr)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrBarrierUnavailable, phase, cause)
	}
	if err := VerifyDDLBarrier(ctx, conn.Conn()); err != nil {
		return releaseRequest(err, "DDL barrier verification")
	}
	// Acquire the shared lock before catalog attestation. Once an exclusive
	// coordinator lock is held, new requests fail fast without querying the
	// catalog; a DCL coordinator cannot pass this request until its lease ends.
	if err := VerifyPostgresRole(ctx, conn.Conn(), b.login, ObserverRole); err != nil {
		return releaseRequest(err, "observer role")
	}
	record, err := readAdmissionHead(ctx, conn)
	if err != nil {
		return releaseRequest(err, "state read")
	}
	if record.Phase != Open {
		if err := releaseRequestBackend(conn); err != nil {
			return nil, fmt.Errorf("%w: release rejected admission: %w", ErrBarrierUnavailable, err)
		}
		return nil, ErrAdmissionClosed
	}
	return &sessionLease{conn: conn, shared: true, ddlShared: true}, nil
}

// CutoverLease holds the exclusive admission session lock. The caller must
// first commit OPEN -> DRAINING through PostgresStore.ApplyVerified. Once
// acquired, every previously admitted request has released both shared locks.
// The coordinator may retain this exclusive admission lock through CLOSED,
// scoped DCL, fresh reader re-attestation and VERIFYING/OPEN: the DDL event
// trigger uses a distinct lock key, so a separate operator LOGIN can execute
// local DCL without conflicting with the coordinator's admission lock. Any
// uncertain outcome must leave the durable state non-OPEN; releasing the lock
// never changes ledger state.
type CutoverLease struct {
	lease *sessionLease
}

func (l *CutoverLease) Release() error {
	if l == nil || l.lease == nil {
		return nil
	}
	return l.lease.Release()
}

// AcquireCutover verifies the independently authenticated Coordinator LOGIN,
// obtains the exclusive lock, and confirms the exact durable non-OPEN record.
// DRAINING is the initial path; CLOSED and VERIFYING are accepted for explicit
// recovery after a lost coordinator/ACK. It never changes state or executes
// DCL. The operator must read back uncertain outcomes; no DCL retry or
// automatic reopen is performed here.
func (b *PostgresBarrier) AcquireCutover(ctx context.Context, expected Record) (*CutoverLease, error) {
	if b == nil || b.pool == nil || b.login == "" || b.mode != CoordinatorRole {
		return nil, ErrBarrierUnavailable
	}
	if !expected.valid() || expected.Phase == Open {
		return nil, ErrInvalid
	}
	conn, err := b.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: acquire coordinator backend: %w", ErrBarrierUnavailable, err)
	}
	if err := VerifyPostgresRole(ctx, conn.Conn(), b.login, CoordinatorRole); err != nil {
		conn.Release()
		return nil, fmt.Errorf("%w: coordinator role: %w", ErrBarrierUnavailable, err)
	}
	// A blocking lock is intentional for the coordinator. Context expiry
	// discards the physical backend because the server may have acquired the
	// session lock just before the client observed cancellation.
	if _, err := conn.Exec(ctx, "SELECT pg_catalog.pg_advisory_lock($1)", admissionBarrierLockKey); err != nil {
		discardBarrierBackend(conn)
		return nil, fmt.Errorf("%w: exclusive lock: %w", ErrBarrierUnavailable, err)
	}
	// Re-attest after waiting for the barrier: a prior DCL may have changed
	// the coordinator's own grants while this backend was queued.
	if err := VerifyPostgresRole(ctx, conn.Conn(), b.login, CoordinatorRole); err != nil {
		if releaseErr := releaseBarrierBackend(conn, false); releaseErr != nil {
			return nil, fmt.Errorf("%w: coordinator role after lock: %v; lock release: %w", ErrBarrierUnavailable, err, releaseErr)
		}
		return nil, fmt.Errorf("%w: coordinator role after lock: %w", ErrBarrierUnavailable, err)
	}
	if err := VerifyDDLBarrier(ctx, conn.Conn()); err != nil {
		if releaseErr := releaseBarrierBackend(conn, false); releaseErr != nil {
			return nil, fmt.Errorf("%w: DDL barrier verification: %v; lock release: %w", ErrBarrierUnavailable, err, releaseErr)
		}
		return nil, fmt.Errorf("%w: DDL barrier verification: %w", ErrBarrierUnavailable, err)
	}
	record, err := readRecord(ctx, conn, false)
	if err != nil {
		if releaseErr := releaseBarrierBackend(conn, false); releaseErr != nil {
			return nil, fmt.Errorf("%w: state read: %v; lock release: %w", ErrBarrierUnavailable, err, releaseErr)
		}
		return nil, fmt.Errorf("%w: state read: %w", ErrBarrierUnavailable, err)
	}
	if record != expected {
		if err := releaseBarrierBackend(conn, false); err != nil {
			return nil, fmt.Errorf("%w: stale state and lock release: %w", ErrBarrierUnavailable, err)
		}
		return nil, ErrConflict
	}
	return &CutoverLease{lease: &sessionLease{conn: conn}}, nil
}

type sessionLease struct {
	conn      *pgxpool.Conn
	shared    bool
	ddlShared bool
	once      sync.Once
	err       error
}

func (l *sessionLease) Release() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.conn == nil {
			l.err = ErrBarrierUnavailable
			return
		}
		if l.ddlShared {
			if err := releaseAdvisoryBackend(l.conn, ddlChangeBarrierLockKey, true); err != nil {
				l.conn = nil
				l.err = err
				return
			}
			l.ddlShared = false
		}
		l.err = releaseBarrierBackend(l.conn, l.shared)
		l.conn = nil
	})
	return l.err
}

func releaseBarrierBackend(conn *pgxpool.Conn, shared bool) error {
	return releaseAdvisoryBackend(conn, admissionBarrierLockKey, shared)
}

// releaseRequestBackend releases the DDL fence first, then admission. This
// lets a queued DDL transaction proceed only after the response is flushed,
// while the coordinator still observes the request as in-flight until both
// locks have been released.
func releaseRequestBackend(conn *pgxpool.Conn) error {
	if err := releaseAdvisoryBackend(conn, ddlChangeBarrierLockKey, true); err != nil {
		return err
	}
	return releaseBarrierBackend(conn, true)
}

func releaseAdvisoryBackend(conn *pgxpool.Conn, key int64, shared bool) error {
	if conn == nil {
		return ErrBarrierUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	function := "pg_advisory_unlock"
	if shared {
		function = "pg_advisory_unlock_shared"
	}
	var unlocked bool
	query := "SELECT pg_catalog." + function + "($1)"
	if err := conn.QueryRow(ctx, query, key).Scan(&unlocked); err != nil {
		discardBarrierBackend(conn)
		return fmt.Errorf("%w: %w", ErrBarrierUnavailable, err)
	}
	if !unlocked {
		discardBarrierBackend(conn)
		return fmt.Errorf("%w: backend did not own advisory lock", ErrBarrierUnavailable)
	}
	// Only release the pooled backend after both request locks are gone.
	if key == admissionBarrierLockKey {
		conn.Release()
	}
	return nil
}

func discardBarrierBackend(conn *pgxpool.Conn) {
	if conn == nil {
		return
	}
	raw := conn.Hijack()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = raw.Close(ctx)
}
