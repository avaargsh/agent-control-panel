package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/authoritycutover"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Two independently authenticated serving replicas hold session-level shared
// admission locks for the entire request. A durable DRAINING record rejects
// new requests; the coordinator's exclusive lock must wait for old requests.
func TestAuthorityCutoverPostgresBarrierCoordinatesIndependentReplicas(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	root, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	roles := []string{}
	// The isolated database cleanup is registered after this callback and
	// therefore runs first; cluster roles are dropped only after the DB.
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		for i := len(roles) - 1; i >= 0; i-- {
			if _, err := root.Exec(cleanup, "DROP ROLE "+pgx.Identifier{roles[i]}.Sanitize()); err != nil {
				t.Errorf("drop role %s: %v", roles[i], err)
			}
		}
		_ = root.Close(cleanup)
	})
	admin, database := isolatedAuthorityRoleTestDatabase(t, ctx, dsn)
	defer admin.Close(context.Background())
	exec := func(query string) {
		t.Helper()
		if _, err := admin.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	createRole := func(name, options string) {
		t.Helper()
		exec("CREATE ROLE " + pgx.Identifier{name}.Sanitize() + " " + options)
		roles = append(roles, name)
	}
	const owner = "acp_cutover_schema_owner"
	const coordinatorGroup = "acp_cutover_coordinator"
	const observerGroup = "acp_cutover_observer"
	createRole(owner, "NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS")
	createRole(coordinatorGroup, "NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS")
	createRole(observerGroup, "NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS")
	exec("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
	exec("GRANT USAGE ON SCHEMA public TO " + owner + ", " + coordinatorGroup + ", " + observerGroup)

	migration, err := os.ReadFile("../../migrations/authority-cutover/0001_state_ledger.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(migration))
	for _, table := range []string{"state", "changes", "transitions"} {
		exec("ALTER TABLE public.acp_authority_cutover_" + table + " OWNER TO " + owner)
	}
	acl, err := os.ReadFile("../../migrations/authority-cutover/0002_table_acl.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec("SET ROLE " + owner)
	exec(string(acl))
	exec("RESET ROLE")

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	login := func(prefix, group string) (*pgxpool.Pool, string) {
		t.Helper()
		name := prefix + suffix
		var secret [24]byte
		if _, err := rand.Read(secret[:]); err != nil {
			t.Fatal(err)
		}
		password := fmt.Sprintf("%x", secret[:])
		createRole(name, "LOGIN INHERIT NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'")
		exec("GRANT " + group + " TO " + pgx.Identifier{name}.Sanitize())
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.Database = database
		cfg.ConnConfig.User = name
		cfg.ConnConfig.Password = password
		cfg.MaxConns = 4
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		var actual string
		if err := pool.QueryRow(ctx, "SELECT session_user").Scan(&actual); err != nil || actual != name {
			t.Fatalf("independent LOGIN not active: got=%q want=%q err=%v", actual, name, err)
		}
		return pool, name
	}
	coordinatorPool, coordinatorLogin := login("acp_cutover_coordinator_", coordinatorGroup)
	replicaAPool, replicaALogin := login("acp_cutover_replica_a_", observerGroup)
	replicaBPool, replicaBLogin := login("acp_cutover_replica_b_", observerGroup)

	// A separate DCL owner performs the test GRANT/REVOKE. The coordinator
	// identity never receives arbitrary schema ownership or DDL privileges.
	dclLogin := "acp_cutover_dcl_" + suffix
	var dclSecret [24]byte
	if _, err := rand.Read(dclSecret[:]); err != nil {
		t.Fatal(err)
	}
	dclPassword := fmt.Sprintf("%x", dclSecret[:])
	createRole(dclLogin, "LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '"+dclPassword+"'")
	exec("CREATE TABLE public.cutover_barrier_secret (id integer PRIMARY KEY)")
	exec("ALTER TABLE public.cutover_barrier_secret OWNER TO " + pgx.Identifier{dclLogin}.Sanitize())
	dclCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	dclCfg.Database, dclCfg.User, dclCfg.Password = database, dclLogin, dclPassword
	dcl, err := pgx.ConnectConfig(ctx, dclCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dcl.Close(context.Background()) })

	store := authoritycutover.NewPostgresStore(coordinatorPool)
	replicaA := authoritycutover.NewPostgresBarrier(replicaAPool, replicaALogin, authoritycutover.ObserverRole)
	replicaB := authoritycutover.NewPostgresBarrier(replicaBPool, replicaBLogin, authoritycutover.ObserverRole)
	coordinator := authoritycutover.NewPostgresBarrier(coordinatorPool, coordinatorLogin, authoritycutover.CoordinatorRole)
	initial := authoritycutover.Record{Generation: 1, Revision: 1, Phase: authoritycutover.Open}
	change := authoritycutover.Change{
		ID: "two-replica-cutover", ManifestDigest: "sha256:" + strings.Repeat("a", 64), Operator: "operator-test",
	}

	// Positive controls: both independently authenticated serving logins are
	// eligible before the cutover begins.
	leaseA, err := replicaA.Acquire(ctx)
	if err != nil {
		t.Fatalf("replica A admission: %v", err)
	}
	leaseB, err := replicaB.Acquire(ctx)
	if err != nil {
		t.Fatalf("replica B admission: %v", err)
	}
	if err := leaseB.Release(); err != nil {
		t.Fatal(err)
	}

	// Persist DRAINING before waiting for the exclusive lock. Requests that
	// race after this commit must fail closed rather than join the drain.
	draining, err := store.ApplyVerified(ctx, coordinatorLogin, initial, authoritycutover.Begin, change)
	if err != nil || draining.Phase != authoritycutover.Draining {
		t.Fatalf("begin durable drain: %+v %v", draining, err)
	}
	if _, err := replicaB.Acquire(ctx); !errors.Is(err, authoritycutover.ErrAdmissionClosed) {
		t.Fatalf("replica B admitted during DRAINING: %v", err)
	}

	// The exclusive coordinator lock cannot pass replica A's in-flight lease.
	waitCtx, waitCancel := context.WithTimeout(ctx, 700*time.Millisecond)
	_, waitErr := coordinator.AcquireCutover(waitCtx, draining)
	waitCancel()
	if !errors.Is(waitErr, context.DeadlineExceeded) && !errors.Is(waitErr, context.Canceled) {
		t.Fatalf("exclusive drain did not wait for in-flight replica A: %v", waitErr)
	}
	if err := leaseA.Release(); err != nil {
		t.Fatal(err)
	}

	cutover, err := coordinator.AcquireCutover(ctx, draining)
	if err != nil {
		t.Fatalf("acquire exclusive drain after replica A completed: %v", err)
	}
	// Simulate coordinator loss after obtaining the barrier but before DCL.
	// Releasing the session lock must NOT reopen the durable DRAINING state.
	if err := cutover.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := replicaA.Acquire(ctx); !errors.Is(err, authoritycutover.ErrAdmissionClosed) {
		t.Fatalf("lost coordinator lock reopened DRAINING state: %v", err)
	}
	cutover, err = coordinator.AcquireCutover(ctx, draining)
	if err != nil {
		t.Fatalf("recovery could not reacquire durable DRAINING state: %v", err)
	}

	closed, err := store.ApplyVerified(ctx, coordinatorLogin, draining, authoritycutover.MarkDrained, change)
	if err != nil || closed.Phase != authoritycutover.Closed {
		t.Fatalf("mark drained: %+v %v", closed, err)
	}
	// A committed out-of-band DCL change is visible to fresh independent
	// observer sessions while the exclusive barrier is still held.
	if _, err := dcl.Exec(ctx, "GRANT SELECT ON public.cutover_barrier_secret TO PUBLIC"); err != nil {
		t.Fatal(err)
	}
	checkRole := func(wantAllowed bool) {
		t.Helper()
		conn, err := replicaAPool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		err = authoritycutover.VerifyPostgresRole(ctx, conn.Conn(), replicaALogin, authoritycutover.ObserverRole)
		if (err == nil) != wantAllowed {
			t.Fatalf("observer role verification allowed=%v want=%v err=%v", err == nil, wantAllowed, err)
		}
	}
	checkRole(false)
	if _, err := replicaB.Acquire(ctx); !errors.Is(err, authoritycutover.ErrAdmissionClosed) {
		t.Fatalf("replica B entered while exclusive cutover lock held: %v", err)
	}
	if _, err := dcl.Exec(ctx, "REVOKE SELECT ON public.cutover_barrier_secret FROM PUBLIC"); err != nil {
		t.Fatal(err)
	}
	checkRole(true)

	verifying, err := store.ApplyVerified(ctx, coordinatorLogin, closed, authoritycutover.ObserveApplied, change)
	if err != nil || verifying.Phase != authoritycutover.Verifying {
		t.Fatalf("record verified DCL: %+v %v", verifying, err)
	}
	opened, err := store.ApplyVerified(ctx, coordinatorLogin, verifying, authoritycutover.Reopen, change)
	if err != nil || opened.Phase != authoritycutover.Open || opened.Generation != 2 {
		t.Fatalf("reopen verified generation: %+v %v", opened, err)
	}
	if err := cutover.Release(); err != nil {
		t.Fatal(err)
	}

	// New admission resumes only after fresh role verification, durable OPEN,
	// and release of the exclusive barrier.
	leaseB, err = replicaB.Acquire(ctx)
	if err != nil {
		t.Fatalf("replica B did not recover after verified reopen: %v", err)
	}
	if err := leaseB.Release(); err != nil {
		t.Fatal(err)
	}
}
