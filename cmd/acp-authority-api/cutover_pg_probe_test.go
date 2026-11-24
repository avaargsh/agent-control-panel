package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestAuthorityCutoverPostgresDrainPrimitive is an isolated experiment, not
// a production admission gate. It tests a candidate serialization primitive
// on two independently authenticated reader backends and an owner backend.
// No HTTP responses, Guard permits or production DCL are involved.
func TestAuthorityCutoverPostgresDrainPrimitive(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, database := isolatedAuthorityRoleTestDatabase(t, ctx, dsn)
	defer admin.Close(context.Background())
	exec := func(conn *pgx.Conn, sql string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(admin, "CREATE TABLE public.cutover_probe (id integer PRIMARY KEY, generation bigint NOT NULL, state text NOT NULL)")
	exec(admin, "INSERT INTO public.cutover_probe VALUES (1,1,'OPEN')")
	exec(admin, "CREATE TABLE public.cutover_payload (id integer PRIMARY KEY)")
	exec(admin, "INSERT INTO public.cutover_payload VALUES (1)")

	reader := func(label string) *pgx.Conn {
		t.Helper()
		role := fmt.Sprintf("acp_cutover_%s_%d", label, time.Now().UnixNano())
		ident := pgx.Identifier{role}.Sanitize()
		secret := make([]byte, 24)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		password := fmt.Sprintf("%x", secret)
		exec(admin, "CREATE ROLE "+ident+" LOGIN PASSWORD '"+password+"'")
		// Use a separate cleanup connection, since admin is deferred closed.
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			cfg, err := pgx.ParseConfig(dsn)
			if err != nil {
				t.Error(err)
				return
			}
			cfg.Database = database
			c, err := pgx.ConnectConfig(cleanup, cfg)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close(cleanup)
			if _, err := c.Exec(cleanup, "DROP OWNED BY "+ident); err != nil {
				t.Error(err)
			}
			if _, err := c.Exec(cleanup, "DROP ROLE "+ident); err != nil {
				t.Error(err)
			}
		})
		exec(admin, "GRANT USAGE ON SCHEMA public TO "+ident)
		exec(admin, "GRANT SELECT ON public.cutover_probe, public.cutover_payload TO "+ident)
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Database, cfg.User, cfg.Password = database, role, password
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		var actual string
		if err := conn.QueryRow(ctx, "SELECT session_user").Scan(&actual); err != nil || actual != role {
			t.Fatalf("independent reader login missing: %q %v", actual, err)
		}
		return conn
	}
	a, b := reader("a"), reader("b")
	if a.PgConn().PID() == b.PgConn().PID() || a.PgConn().PID() == admin.PgConn().PID() || b.PgConn().PID() == admin.PgConn().PID() {
		t.Fatal("cutover probe requires three distinct PostgreSQL backends")
	}
	const key int64 = 980024
	admit := func(conn *pgx.Conn) (pgx.Tx, int64, bool) {
		t.Helper()
		tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		var locked bool
		if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock_shared($1)", key).Scan(&locked); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if !locked {
			_ = tx.Rollback(ctx)
			return nil, 0, false
		}
		var generation int64
		var state string
		if err := tx.QueryRow(ctx, "SELECT generation,state FROM public.cutover_probe WHERE id=1").Scan(&generation, &state); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if state != "OPEN" {
			_ = tx.Rollback(ctx)
			return nil, generation, false
		}
		return tx, generation, true
	}
	reject := func(conn *pgx.Conn) {
		t.Helper()
		if tx, _, ok := admit(conn); ok {
			_ = tx.Rollback(ctx)
			t.Fatal("new reader admitted during closed cutover")
		}
	}

	inflight, generation, ok := admit(a)
	if !ok || generation != 1 {
		t.Fatal("old reader did not acquire positive admission")
	}
	defer inflight.Rollback(context.Background())
	exec(admin, "UPDATE public.cutover_probe SET state='DRAINING' WHERE id=1 AND generation=1 AND state='OPEN'")
	reject(b)

	change, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer change.Rollback(context.Background())
	var drained bool
	if err := change.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", key).Scan(&drained); err != nil || drained {
		t.Fatalf("exclusive cutover passed an in-flight reader: drained=%v err=%v", drained, err)
	}
	if err := inflight.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := change.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", key).Scan(&drained); err != nil || !drained {
		t.Fatalf("exclusive drain failed after reader completion: drained=%v err=%v", drained, err)
	}
	reject(b)
	// Simulate an operator abort after drain but before an acknowledged
	// cutover. Transaction lock release alone must not reopen admission.
	if err := change.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	reject(a)
	reject(b)

	// Explicit owner recovery acquires the barrier again. This deliberately
	// changes only a disposable probe table's ACL, not any real service role.
	change, err = admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer change.Rollback(context.Background())
	if err := change.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", key).Scan(&drained); err != nil || !drained {
		t.Fatalf("recovery cannot acquire drain: %v %v", drained, err)
	}
	var role string
	if err := b.QueryRow(ctx, "SELECT session_user").Scan(&role); err != nil {
		t.Fatal(err)
	}
	if _, err := change.Exec(ctx, "REVOKE SELECT ON public.cutover_payload FROM "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err := change.Exec(ctx, "UPDATE public.cutover_probe SET generation=2,state='VERIFYING' WHERE id=1 AND generation=1 AND state='DRAINING'"); err != nil {
		t.Fatal(err)
	}
	if err := change.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	reject(a)
	reject(b)
	var allowed bool
	if err := b.QueryRow(ctx, "SELECT has_table_privilege(session_user,'public.cutover_payload','SELECT')").Scan(&allowed); err != nil || allowed {
		t.Fatalf("committed ACL change was not observed: allowed=%v err=%v", allowed, err)
	}
	// Restore the disposable ACL before manually reopening. This is not
	// real role attestation or implementation of the production coordinator.
	exec(admin, "GRANT SELECT ON public.cutover_payload TO "+pgx.Identifier{role}.Sanitize())
	exec(admin, "UPDATE public.cutover_probe SET state='OPEN' WHERE id=1 AND generation=2 AND state='VERIFYING'")
	for _, conn := range []*pgx.Conn{a, b} {
		tx, got, ok := admit(conn)
		if !ok || got != 2 {
			t.Fatalf("explicit reopen did not admit new generation: %d %v", got, ok)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
