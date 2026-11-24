package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// This is a disposable SQL contract experiment for #98, not a production
// coordinator or a proof of distributed HTTP admission. A stale change must
// never reopen a newer generation, including after a connection is lost.
func TestAuthorityCutoverPostgresGenerationCAS(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, database := isolatedAuthorityRoleTestDatabase(t, ctx, dsn)
	defer owner.Close(context.Background())
	if _, err := owner.Exec(ctx, `CREATE TABLE public.cutover_cas (
		id integer PRIMARY KEY CHECK (id=1),
		generation bigint NOT NULL CHECK (generation>0),
		state text NOT NULL CHECK (state IN ('OPEN','DRAINING','CLOSED','VERIFYING')),
		change_id text NOT NULL,
		manifest text NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, "INSERT INTO public.cutover_cas VALUES (1,1,'OPEN','','')"); err != nil {
		t.Fatal(err)
	}
	connect := func() *pgx.Conn {
		t.Helper()
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Database = database
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	recovery := connect()
	if owner.PgConn().PID() == recovery.PgConn().PID() {
		t.Fatal("expected distinct coordinator backends")
	}
	type record struct {
		generation int64
		state      string
		change     string
		manifest   string
	}
	observe := func(c *pgx.Conn, want record) {
		t.Helper()
		var got record
		if err := c.QueryRow(ctx, "SELECT generation,state,change_id,manifest FROM public.cutover_cas WHERE id=1").Scan(&got.generation, &got.state, &got.change, &got.manifest); err != nil || got != want {
			t.Fatalf("unexpected durable record: got=%+v want=%+v err=%v", got, want, err)
		}
	}
	// Every state transition compares the full previous identity, not just
	// the state label. A zero-row result is a conflict, never success.
	cas := func(c *pgx.Conn, from, to record, wantRows int64) {
		t.Helper()
		tag, err := c.Exec(ctx, `UPDATE public.cutover_cas
			SET generation=$1,state=$2,change_id=$3,manifest=$4
			WHERE id=1 AND generation=$5 AND state=$6 AND change_id=$7 AND manifest=$8`,
			to.generation, to.state, to.change, to.manifest,
			from.generation, from.state, from.change, from.manifest)
		if err != nil || tag.RowsAffected() != wantRows {
			t.Fatalf("CAS %s -> %s: rows=%d want=%d err=%v", from.state, to.state, tag.RowsAffected(), wantRows, err)
		}
	}
	open := record{1, "OPEN", "", ""}
	draining := record{1, "DRAINING", "change-a", "manifest-a"}
	closed := record{1, "CLOSED", "change-a", "manifest-a"}
	verifying := record{2, "VERIFYING", "change-a", "manifest-a"}
	next := record{2, "OPEN", "", ""}
	cas(owner, open, draining, 1)
	cas(recovery, open, record{1, "DRAINING", "change-b", "manifest-b"}, 0)
	observe(recovery, draining)

	// Lose the original coordinator session after committed admission close.
	// Recovery reads the exact durable state; it cannot reopen via an old
	// OPEN token or advance a command with a different manifest.
	if err := owner.Close(ctx); err != nil {
		t.Fatal(err)
	}
	observe(recovery, draining)
	cas(recovery, record{1, "DRAINING", "change-a", "forged-manifest"}, closed, 0)
	cas(recovery, open, next, 0)
	cas(recovery, draining, closed, 1)

	// Roll back an uncommitted transition, then reconnect. Uncertain progress
	// must not be mistaken for a successful generation increase.
	tx, err := recovery.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "UPDATE public.cutover_cas SET generation=2,state='VERIFYING' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := recovery.Close(ctx); err != nil {
		t.Fatal(err)
	}
	fresh := connect()
	observe(fresh, closed)
	cas(fresh, verifying, next, 0)
	cas(fresh, closed, verifying, 1)
	observe(fresh, verifying)
	// Explicit re-attestation is outside this SQL probe. The following
	// transition represents a test owner accepting the new manifest.
	cas(fresh, verifying, next, 1)
	observe(fresh, next)
	cas(fresh, verifying, next, 0)
	cas(fresh, closed, verifying, 0)
	cas(fresh, open, draining, 0)
	observe(fresh, next)
}
