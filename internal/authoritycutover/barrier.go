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
const admissionBarrierLockKey int64 = 0x4143504355544f56

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
	// The advisory lock coordinates cooperative replicas. It cannot fence an
	// arbitrary DBA, so hold PostgreSQL ACL catalogs in SHARE mode for the
	// complete request transaction as well. GRANT/REVOKE updates acquire
	// conflicting ROW EXCLUSIVE locks on these catalogs and therefore cannot
	// commit between role attestation, authority reads and the final response
	// flush. The observer LOGIN has no write grants; READ WRITE is requested
	// only because PostgreSQL requires a read-write transaction for LOCK TABLE.
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		if releaseErr := releaseBarrierBackend(conn, true); releaseErr != nil {
			return nil, fmt.Errorf("%w: begin catalog fence: %v; lock release: %w", ErrBarrierUnavailable, err, releaseErr)
		}
		return nil, fmt.Errorf("%w: begin catalog fence: %w", ErrBarrierUnavailable, err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE
		pg_catalog.pg_class,
		pg_catalog.pg_attribute,
		pg_catalog.pg_proc,
		pg_catalog.pg_namespace,
		pg_catalog.pg_auth_members,
		pg_catalog.pg_database
		IN SHARE MODE`); err != nil {
		if releaseErr := rollbackAndReleaseBarrierBackend(conn, tx, true); releaseErr != nil {
			return nil, fmt.Errorf("%w: acquire ACL catalog fence: %v; cleanup: %w", ErrBarrierUnavailable, err, releaseErr)
		}
		return nil, fmt.Errorf("%w: acquire ACL catalog fence: %w", ErrBarrierUnavailable, err)
	}
	// Attest only after the ACL catalogs are pinned. A DCL operation that
	// committed before the locks were acquired is visible to this probe; one
	// that starts afterwards must wait until the request lease is released.
	if err := VerifyPostgresRole(ctx, conn.Conn(), b.login, ObserverRole); err != nil {
		if releaseErr := rollbackAndReleaseBarrierBackend(conn, tx, true); releaseErr != nil {
			return nil, fmt.Errorf("%w: observer role: %v; cleanup: %w", ErrBarrierUnavailable, err, releaseErr)
		}
		return nil, fmt.Errorf("%w: observer role: %w", ErrBarrierUnavailable, err)
	}
	record, err := readAdmissionHead(ctx, tx)
	if err != nil {
		if releaseErr := rollbackAndReleaseBarrierBackend(conn, tx, true); releaseErr != nil {
			return nil, fmt.Errorf("%w: state read: %v; cleanup: %w", ErrBarrierUnavailable, err, releaseErr)
		}
		return nil, fmt.Errorf("%w: state read: %w", ErrBarrierUnavailable, err)
	}
	if record.Phase != Open {
		if err := rollbackAndReleaseBarrierBackend(conn, tx, true); err != nil {
			return nil, fmt.Errorf("%w: release rejected admission: %w", ErrBarrierUnavailable, err)
		}
		return nil, ErrAdmissionClosed
	}
	return &sessionLease{conn: conn, tx: tx, shared: true}, nil
}

// CutoverLease holds the exclusive session lock. The caller must first commit
// OPEN -> DRAINING through PostgresStore.ApplyVerified. Once acquired, every
// previously admitted request has released its shared lease. The coordinator
// may then persist CLOSED, execute scoped DCL with its separate operator
// identity, independently re-attest reader LOGINS, persist VERIFYING/OPEN,
// and only then release this lease. Any uncertain outcome must leave the
// durable state non-OPEN; releasing the lock never changes ledger state.
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
	conn   *pgxpool.Conn
	tx     pgx.Tx
	shared bool
	once   sync.Once
	err    error
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
		if l.tx != nil {
			if err := rollbackBarrierTransaction(l.tx); err != nil {
				discardBarrierBackend(l.conn)
				l.conn = nil
				l.tx = nil
				l.err = fmt.Errorf("%w: release ACL catalog fence: %w", ErrBarrierUnavailable, err)
				return
			}
			l.tx = nil
		}
		l.err = releaseBarrierBackend(l.conn, l.shared)
		l.conn = nil
	})
	return l.err
}

func rollbackBarrierTransaction(tx pgx.Tx) error {
	if tx == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

func rollbackAndReleaseBarrierBackend(conn *pgxpool.Conn, tx pgx.Tx, shared bool) error {
	if err := rollbackBarrierTransaction(tx); err != nil {
		discardBarrierBackend(conn)
		return err
	}
	return releaseBarrierBackend(conn, shared)
}

func releaseBarrierBackend(conn *pgxpool.Conn, shared bool) error {
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
	if err := conn.QueryRow(ctx, query, admissionBarrierLockKey).Scan(&unlocked); err != nil {
		discardBarrierBackend(conn)
		return fmt.Errorf("%w: %w", ErrBarrierUnavailable, err)
	}
	if !unlocked {
		discardBarrierBackend(conn)
		return fmt.Errorf("%w: backend did not own advisory lock", ErrBarrierUnavailable)
	}
	conn.Release()
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
