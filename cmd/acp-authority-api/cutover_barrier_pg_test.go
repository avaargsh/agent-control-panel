package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sort"
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
	if !samePostgresPrimary(ctx, coordinatorPool, replicaAPool) ||
		!samePostgresPrimary(ctx, replicaAPool, replicaBPool) {
		t.Fatal("serving replicas and coordinator did not resolve to the same PostgreSQL primary")
	}

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
	// Observe the real PostgreSQL lock waiter, then revoke the coordinator
	// membership while it is queued. Post-lock re-attestation must reject it.
	drainStarted := time.Now()
	type cutoverResult struct {
		lease *authoritycutover.CutoverLease
		err   error
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 10*time.Second)
	waiting := make(chan cutoverResult, 1)
	go func() {
		lease, err := coordinator.AcquireCutover(waitCtx, draining)
		waiting <- cutoverResult{lease: lease, err: err}
	}()
	waiterSeen := false
	waitDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(waitDeadline) {
		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_locks
			WHERE locktype='advisory' AND NOT granted
			AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())`).Scan(&count); err != nil {
			waitCancel()
			t.Fatal(err)
		}
		if count > 0 {
			waiterSeen = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiterSeen {
		waitCancel()
		t.Fatal("PostgreSQL did not expose the coordinator as waiting behind replica A")
	}
	if _, err := admin.Exec(ctx, "REVOKE "+pgx.Identifier{coordinatorGroup}.Sanitize()+" FROM "+pgx.Identifier{coordinatorLogin}.Sanitize()); err != nil {
		waitCancel()
		t.Fatal(err)
	}
	if err := leaseA.Release(); err != nil {
		waitCancel()
		t.Fatal(err)
	}
	waitResult := <-waiting
	waitCancel()
	if waitResult.lease != nil {
		_ = waitResult.lease.Release()
	}
	if !errors.Is(waitResult.err, authoritycutover.ErrBarrierUnavailable) {
		t.Fatalf("coordinator role drift while queued was not rejected after exclusive lock: %v", waitResult.err)
	}
	t.Logf("two-replica drain wait including held in-flight lease and post-lock re-attestation: %s", time.Since(drainStarted))
	if _, err := admin.Exec(ctx, "GRANT "+pgx.Identifier{coordinatorGroup}.Sanitize()+" TO "+pgx.Identifier{coordinatorLogin}.Sanitize()); err != nil {
		t.Fatal(err)
	}

	cutover, err := coordinator.AcquireCutover(ctx, draining)
	if err != nil {
		t.Fatalf("acquire exclusive drain after restoring coordinator role: %v", err)
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
	// The exclusive lock blocks a fresh replica even after durable CLOSED.
	if _, err := replicaB.Acquire(ctx); !errors.Is(err, authoritycutover.ErrAdmissionClosed) {
		t.Fatalf("replica B entered while exclusive cutover lock held: %v", err)
	}
	// Simulate coordinator loss after MarkDrained. Releasing the session lock
	// must not reopen CLOSED; recovery must reacquire against the exact record.
	if err := cutover.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := replicaA.Acquire(ctx); !errors.Is(err, authoritycutover.ErrAdmissionClosed) {
		t.Fatalf("coordinator loss reopened CLOSED state: %v", err)
	}
	cutover, err = coordinator.AcquireCutover(ctx, closed)
	if err != nil {
		t.Fatalf("coordinator could not recover CLOSED state: %v", err)
	}

	// Commit a DCL grant, then simulate a lost ACK by dropping the coordinator
	// lock without advancing the durable state. Recovery must read actual ACLs
	// and must not reopen merely because the lock/session was lost.
	if _, err := dcl.Exec(ctx, "GRANT SELECT ON public.cutover_barrier_secret TO PUBLIC"); err != nil {
		t.Fatal(err)
	}
	if err := cutover.Release(); err != nil {
		t.Fatal(err)
	}
	// PUBLIC drift affects both the coordinator and serving identities. Do
	// not weaken their attestation or use the unverified Store as a fallback.
	if got, err := store.ObserveVerified(ctx, coordinatorLogin, authoritycutover.CoordinatorRole); !errors.Is(err, authoritycutover.ErrRoleDrift) || got != (authoritycutover.Record{}) {
		t.Fatalf("coordinator returned a record despite live PUBLIC drift: got=%+v err=%v", got, err)
	}
	if _, err := replicaB.Acquire(ctx); !errors.Is(err, authoritycutover.ErrBarrierUnavailable) {
		t.Fatalf("observer with live DCL drift was not denied after lost ACK: %v", err)
	}
	if unexpected, err := coordinator.AcquireCutover(ctx, closed); !errors.Is(err, authoritycutover.ErrBarrierUnavailable) || unexpected != nil {
		if unexpected != nil {
			_ = unexpected.Release()
		}
		t.Fatalf("coordinator reacquired cutover despite live PUBLIC drift: %v", err)
	}
	// Independently inspect the durable state with the test-only database
	// administrator, not the drifted production-facing credentials.
	var durableAfterLostACK authoritycutover.Record
	var phase string
	if err := admin.QueryRow(ctx, `SELECT generation,revision,phase,change_id,manifest_digest,operator_id
		FROM public.acp_authority_cutover_state WHERE id=1`).Scan(
		&durableAfterLostACK.Generation, &durableAfterLostACK.Revision, &phase,
		&durableAfterLostACK.Change.ID, &durableAfterLostACK.Change.ManifestDigest, &durableAfterLostACK.Change.Operator,
	); err != nil {
		t.Fatal(err)
	}
	durableAfterLostACK.Phase = authoritycutover.Phase(phase)
	if durableAfterLostACK != closed {
		t.Fatalf("lost DCL ACK changed durable CLOSED record: got=%+v want=%+v", durableAfterLostACK, closed)
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
	if _, err := dcl.Exec(ctx, "REVOKE SELECT ON public.cutover_barrier_secret FROM PUBLIC"); err != nil {
		t.Fatal(err)
	}
	checkRole(true)
	if got, err := store.ObserveVerified(ctx, coordinatorLogin, authoritycutover.CoordinatorRole); err != nil || got != closed {
		t.Fatalf("restored coordinator did not observe original CLOSED record: got=%+v err=%v", got, err)
	}
	if _, err := replicaB.Acquire(ctx); !errors.Is(err, authoritycutover.ErrAdmissionClosed) {
		t.Fatalf("restored role implicitly reopened CLOSED state: %v", err)
	}
	cutover, err = coordinator.AcquireCutover(ctx, closed)
	if err != nil {
		t.Fatalf("restored coordinator could not reacquire original CLOSED state: %v", err)
	}

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

	// Record a bounded PG16 microbenchmark for the real admission path. This
	// is not an HTTP SLO or production latency claim; it exposes the incremental
	// catalog-probe cost and connection-pool footprint to the CI log.
	const samplesN = 100
	baseline := make([]time.Duration, samplesN)
	admission := make([]time.Duration, samplesN)
	for i := 0; i < samplesN; i++ {
		start := time.Now()
		var one int
		if err := replicaAPool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
			t.Fatalf("baseline query: value=%d err=%v", one, err)
		}
		baseline[i] = time.Since(start)

		start = time.Now()
		lease, err := replicaA.Acquire(ctx)
		if err != nil {
			t.Fatalf("post-reopen admission sample %d: %v", i, err)
		}
		if err := lease.Release(); err != nil {
			t.Fatalf("post-reopen lease release %d: %v", i, err)
		}
		admission[i] = time.Since(start)
	}
	sort.Slice(baseline, func(i, j int) bool { return baseline[i] < baseline[j] })
	sort.Slice(admission, func(i, j int) bool { return admission[i] < admission[j] })
	stat := replicaAPool.Stat()
	t.Logf("PG16 admission microbenchmark n=%d baseline_ms p50=%.3f p95=%.3f p99=%.3f; gated_ms p50=%.3f p95=%.3f p99=%.3f; pool_total=%d pool_idle=%d",
		samplesN,
		float64(baseline[49])/float64(time.Millisecond), float64(baseline[94])/float64(time.Millisecond), float64(baseline[98])/float64(time.Millisecond),
		float64(admission[49])/float64(time.Millisecond), float64(admission[94])/float64(time.Millisecond), float64(admission[98])/float64(time.Millisecond),
		stat.TotalConns(), stat.IdleConns())
}
