package authoritycutover

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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
	if primaryDSN == "" || standbyDSN == "" {
		t.Skip("both PostgreSQL fixture DSNs are required")
	}
	if os.Getenv("PGTEST_ALLOW_STANDBY_PROMOTION") != "1" {
		t.Skip("standby promotion requires explicit disposable-fixture opt-in")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	primaryConfig, err := pgxpool.ParseConfig(primaryDSN)
	if err != nil {
		t.Fatal("invalid primary fixture DSN")
	}
	standbyConfig, err := pgxpool.ParseConfig(standbyDSN)
	if err != nil {
		t.Fatal("invalid standby fixture DSN")
	}
	if primaryConfig.ConnConfig.Host != "127.0.0.1" ||
		standbyConfig.ConnConfig.Host != "127.0.0.1" ||
		primaryConfig.ConnConfig.Port == standbyConfig.ConnConfig.Port ||
		primaryConfig.ConnConfig.Database != standbyConfig.ConnConfig.Database {
		t.Fatal("promotion regression requires distinct loopback fixture endpoints for the same database")
	}

	fence := NewPrimaryFence()
	var reroute atomic.Bool
	type fixturePool struct {
		name             string
		pool             *pgxpool.Pool
		standbyRejected  atomic.Int64
		promotedRejected atomic.Int64
	}

	newFencedPool := func(name string) *fixturePool {
		t.Helper()
		fixture := &fixturePool{name: name}
		cfg := primaryConfig.Copy()
		cfg.MaxConns = 1
		cfg.ConnConfig.Fallbacks = nil
		cfg.BeforeConnect = func(_ context.Context, connConfig *pgx.ConnConfig) error {
			if reroute.Load() {
				connConfig.Host = standbyConfig.ConnConfig.Host
				connConfig.Port = standbyConfig.ConnConfig.Port
			}
			return nil
		}
		cfg.BeforeAcquire = func(acquireCtx context.Context, conn *pgx.Conn) bool {
			allowed := fence.BeforeAcquire(acquireCtx, conn)
			if !allowed && reroute.Load() {
				var inRecovery bool
				var port int
				if err := conn.QueryRow(acquireCtx, "SELECT pg_is_in_recovery(), inet_server_port()").Scan(&inRecovery, &port); err == nil &&
					port == int(standbyConfig.ConnConfig.Port) {
					if inRecovery {
						fixture.standbyRejected.Add(1)
					} else {
						fixture.promotedRejected.Add(1)
					}
				}
			}
			return allowed
		}
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("create %s pool: %v", name, err)
		}
		fixture.pool = pool
		t.Cleanup(pool.Close)
		return fixture
	}

	authority := newFencedPool("authority")
	cutover := newFencedPool("cutover")
	if err := fence.Initialize(ctx, authority.pool, cutover.pool); err != nil {
		t.Fatalf("pin the original writable primary: %v", err)
	}
	for _, fixture := range []*fixturePool{authority, cutover} {
		var port int
		if err := fixture.pool.QueryRow(ctx, "SELECT inet_server_port()").Scan(&port); err != nil || port != int(primaryConfig.ConnConfig.Port) {
			t.Fatalf("%s positive control did not reach the pinned primary: port=%d err=%v", fixture.name, port, err)
		}
	}

	standbyProbe, err := pgxpool.NewWithConfig(ctx, standbyConfig)
	if err != nil {
		t.Fatalf("create independent standby probe: %v", err)
	}
	t.Cleanup(standbyProbe.Close)
	var inRecovery bool
	if err := standbyProbe.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&inRecovery); err != nil || !inRecovery {
		t.Fatalf("physical standby positive control failed: recovery=%t err=%v", inRecovery, err)
	}

	// Keep both original pools and the pinned fence. Reset only their
	// connections so the next dial follows the fixture's changed endpoint.
	reroute.Store(true)
	authority.pool.Reset()
	cutover.pool.Reset()
	rejectAcquire := func(fixture *fixturePool, promoted bool) {
		t.Helper()
		acquireCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		conn, err := fixture.pool.Acquire(acquireCtx)
		if err == nil {
			conn.Release()
			t.Fatalf("%s admitted a different backend (promoted=%t)", fixture.name, promoted)
		}
		if (!promoted && fixture.standbyRejected.Load() == 0) ||
			(promoted && fixture.promotedRejected.Load() == 0) {
			t.Fatalf("%s did not observe a fence rejection on the expected live backend (promoted=%t): %v", fixture.name, promoted, err)
		}
	}
	for _, fixture := range []*fixturePool{authority, cutover} {
		rejectAcquire(fixture, false)
	}

	// Only the explicitly opted-in disposable loopback standby is promoted.
	var promoted bool
	if err := standbyProbe.QueryRow(ctx, "SELECT pg_promote(true, 30)").Scan(&promoted); err != nil || !promoted {
		t.Fatalf("fixture standby promotion failed: promoted=%t err=%v", promoted, err)
	}
	if err := standbyProbe.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&inRecovery); err != nil || inRecovery {
		t.Fatalf("promoted server positive control failed: recovery=%t err=%v", inRecovery, err)
	}

	for _, fixture := range []*fixturePool{authority, cutover} {
		fixture.pool.Reset()
		rejectAcquire(fixture, true)
		queryCtx, stopQuery := context.WithTimeout(ctx, 3*time.Second)
		var result string
		err := fixture.pool.QueryRow(queryCtx, "SELECT 'unexpected-authority-result'").Scan(&result)
		stopQuery()
		if err == nil {
			t.Fatalf("%s returned authority data from a different primary: %q", fixture.name, result)
		}
	}
}
