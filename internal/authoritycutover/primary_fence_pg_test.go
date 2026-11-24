package authoritycutover

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPrimaryFencePinsBothPoolsToOneWritablePostgresBackend(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is required for real PostgreSQL primary identity verification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fence := NewPrimaryFence()
	newPool := func(database string, beforeAcquire bool) *pgxpool.Pool {
		t.Helper()
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatalf("parse PGTEST_DSN: %v", err)
		}
		if database != "" {
			cfg.ConnConfig.Database = database
		}
		cfg.MaxConns = 2
		if beforeAcquire {
			cfg.BeforeAcquire = fence.BeforeAcquire
		}
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("create PostgreSQL pool for %s: %v", cfg.ConnConfig.Database, err)
		}
		t.Cleanup(pool.Close)
		return pool
	}

	authority := newPool("", true)
	cutover := newPool("", true)
	if err := fence.Initialize(ctx, authority, cutover); err != nil {
		t.Fatalf("same writable PostgreSQL primary was not pinned: %v", err)
	}
	for name, pool := range map[string]*pgxpool.Pool{
		"authority": authority,
		"cutover":   cutover,
	} {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("%s pool could not reacquire its pinned primary: %v", name, err)
		}
		if !fence.accept(ctx, conn.Conn()) {
			conn.Release()
			t.Fatalf("%s pool admitted a backend outside the pinned primary", name)
		}
		conn.Release()
	}

	otherDatabase := newPool("template1", false)
	if err := NewPrimaryFence().Initialize(ctx, authority, otherDatabase); !errors.Is(err, ErrPrimaryIdentityUnavailable) {
		t.Fatalf("different PostgreSQL database was not rejected: %v", err)
	}
}

func TestPrimaryFenceRejectsStandbyAndPromotedPrimaryAfterFailover(t *testing.T) {
	primaryDSN := os.Getenv("PGTEST_DSN")
	standbyDSN := os.Getenv("PGTEST_STANDBY_DSN")
	if primaryDSN == "" {
		t.Skip("PGTEST_DSN is required for real PostgreSQL failover fencing verification")
	}
	if standbyDSN == "" {
		t.Fatal("PGTEST_STANDBY_DSN is required when PGTEST_DSN is configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fence := NewPrimaryFence()
	newPool := func(dsn string, beforeAcquire bool) *pgxpool.Pool {
		t.Helper()
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatalf("parse PostgreSQL DSN: %v", err)
		}
		cfg.MaxConns = 1
		if beforeAcquire {
			cfg.BeforeAcquire = fence.BeforeAcquire
		}
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("create PostgreSQL pool: %v", err)
		}
		t.Cleanup(pool.Close)
		return pool
	}

	authority := newPool(primaryDSN, true)
	cutover := newPool(primaryDSN, true)
	if err := fence.Initialize(ctx, authority, cutover); err != nil {
		t.Fatalf("pin the original writable primary: %v", err)
	}

	standbyProbe := newPool(standbyDSN, false)
	var inRecovery bool
	if err := standbyProbe.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&inRecovery); err != nil {
		t.Fatalf("inspect physical standby before failover: %v", err)
	}
	if !inRecovery {
		t.Fatal("PGTEST_STANDBY_DSN must point to a physical standby before promotion")
	}

	// Model a pool reconnecting through an endpoint that now routes to a
	// standby. The per-connection callback must reject it before any query
	// can return an authority result.
	reroutedPool := newPool(standbyDSN, true)
	rejectAcquire := func(stage string) {
		t.Helper()
		acquireCtx, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		conn, err := reroutedPool.Acquire(acquireCtx)
		if err == nil {
			conn.Release()
			t.Fatalf("primary fence admitted a rerouted backend %s", stage)
		}
	}
	rejectAcquire("while it is in recovery")

	// Promote the standby to simulate a real failover. It is writable now,
	// but it is not the postmaster identity pinned at service startup.
	var promoted bool
	if err := standbyProbe.QueryRow(ctx, "SELECT pg_promote(true, 30)").Scan(&promoted); err != nil {
		t.Fatalf("promote standby for failover regression: %v", err)
	}
	if !promoted {
		t.Fatal("PostgreSQL did not promote the standby")
	}

	promotionCtx, stopPromotion := context.WithTimeout(ctx, 30*time.Second)
	defer stopPromotion()
	for {
		if err := standbyProbe.QueryRow(promotionCtx, "SELECT pg_is_in_recovery()").Scan(&inRecovery); err == nil && !inRecovery {
			break
		}
		if promotionCtx.Err() != nil {
			t.Fatalf("promoted PostgreSQL server did not leave recovery: %v", promotionCtx.Err())
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The same pool now reconnects to a writable but different postmaster.
	// Identity mismatch must still fail closed; writability alone is not
	// sufficient to move the admission barrier after uncertain failover.
	rejectAcquire("after it has been promoted to a different primary")

	queryCtx, stopQuery := context.WithTimeout(ctx, 2*time.Second)
	defer stopQuery()
	var result string
	err := reroutedPool.QueryRow(queryCtx, "SELECT 'unexpected-authority-result'").Scan(&result)
	if err == nil {
		t.Fatalf("rerouted pool returned authority data from a different primary: %q", result)
	}
}
