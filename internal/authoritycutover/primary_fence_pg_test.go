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
