package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/authoritycutover"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A disposable schema fixture, not a deployment migration. The proposed store
// is owner-only and is not connected to the existing Authority HTTP listener.
func TestAuthorityCutoverPostgresStoreContract(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, database := isolatedAuthorityRoleTestDatabase(t, ctx, dsn)
	defer admin.Close(context.Background())
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE TABLE public.acp_authority_cutover_state (
		id integer PRIMARY KEY CHECK (id=1),
		generation bigint NOT NULL CHECK (generation>0),
		revision bigint NOT NULL CHECK (revision>=generation),
		phase text NOT NULL CHECK (phase IN ('OPEN','DRAINING','CLOSED','VERIFYING')),
		change_id text NOT NULL,
		manifest_digest text NOT NULL,
		operator_id text NOT NULL
	)`)
	exec(`CREATE TABLE public.acp_authority_cutover_changes (
		change_id text PRIMARY KEY,
		manifest_digest text NOT NULL,
		operator_id text NOT NULL,
		start_generation bigint NOT NULL CHECK (start_generation>0)
	)`)
	exec(`CREATE TABLE public.acp_authority_cutover_transitions (
		revision bigint PRIMARY KEY CHECK (revision>1),
		generation bigint NOT NULL CHECK (generation>0),
		phase text NOT NULL CHECK (phase IN ('OPEN','DRAINING','CLOSED','VERIFYING')),
		change_id text NOT NULL REFERENCES public.acp_authority_cutover_changes(change_id),
		manifest_digest text NOT NULL,
		operator_id text NOT NULL
	)`)
	pool := func() *pgxpool.Pool {
		t.Helper()
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.Database = database
		p, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	poolA, poolB := pool(), pool()
	a := authoritycutover.NewPostgresStore(poolA)
	b := authoritycutover.NewPostgresStore(poolB)
	if _, err := a.Observe(ctx); err == nil {
		t.Fatal("missing coordinator state was treated as OPEN")
	}
	exec("INSERT INTO public.acp_authority_cutover_state VALUES (1,1,1,'OPEN','','','')")
	initial := authoritycutover.Record{Generation: 1, Revision: 1, Phase: authoritycutover.Open}
	observe := func(store *authoritycutover.PostgresStore, want authoritycutover.Record) {
		t.Helper()
		got, err := store.Observe(ctx)
		if err != nil || got != want {
			t.Fatalf("observed record: got=%+v want=%+v err=%v", got, want, err)
		}
	}
	observe(a, initial)
	first := authoritycutover.Change{ID: "change-a", ManifestDigest: "sha256:" + strings.Repeat("a", 64), Operator: "operator-a"}
	second := authoritycutover.Change{ID: "change-b", ManifestDigest: "sha256:" + strings.Repeat("b", 64), Operator: "operator-b"}
	// Force the state update to fail after the change claim, whatever the
	// statement ordering. Neither the state nor the claim may survive.
	exec("ALTER TABLE public.acp_authority_cutover_state ADD CONSTRAINT reject_probe_drain CHECK (phase<>'DRAINING')")
	if _, err := a.Apply(ctx, initial, authoritycutover.Begin, first); err == nil {
		t.Fatal("forced state constraint failure reported success")
	}
	observe(b, initial)
	var count int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_changes").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed transition leaked durable change claim: %d %v", count, err)
	}
	exec("ALTER TABLE public.acp_authority_cutover_state DROP CONSTRAINT reject_probe_drain")

	// The state, change claim and transition history must commit together.
	exec("ALTER TABLE public.acp_authority_cutover_transitions ADD CONSTRAINT reject_probe_transition CHECK (revision<>2)")
	if _, err := a.Apply(ctx, initial, authoritycutover.Begin, first); err == nil {
		t.Errorf("transition history constraint failure reported success")
	}
	var transitionCount int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_transitions").Scan(&transitionCount); err != nil || transitionCount != 0 {
		t.Fatalf("failed transaction leaked transition history: %d %v", transitionCount, err)
	}
	observe(a, initial)
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_changes").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed history write leaked change claim: %d %v", count, err)
	}
	exec("ALTER TABLE public.acp_authority_cutover_transitions DROP CONSTRAINT reject_probe_transition")
	observe(a, initial)

	type outcome struct {
		record authoritycutover.Record
		change authoritycutover.Change
		err    error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	for _, worker := range []struct {
		store  *authoritycutover.PostgresStore
		change authoritycutover.Change
	}{{a, first}, {b, second}} {
		go func() {
			<-start
			got, err := worker.store.Apply(ctx, initial, authoritycutover.Begin, worker.change)
			results <- outcome{got, worker.change, err}
		}()
	}
	close(start)
	var winner outcome
	successes, conflicts := 0, 0
	for i := 0; i < 2; i++ {
		result := <-results
		switch {
		case result.err == nil:
			winner = result
			successes++
		case errors.Is(result.err, authoritycutover.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected CAS result: %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("two coordinators did not serialize: successes=%d conflicts=%d", successes, conflicts)
	}
	observe(a, winner.record)
	observe(b, winner.record)
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_changes").Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected exactly one committed change claim: %d %v", count, err)
	}

	// Restart the owner adapter with a new pool. No in-memory claim or state
	// may be required to finish an already committed cutover.
	poolA.Close()
	poolB.Close()
	fresh := authoritycutover.NewPostgresStore(pool())
	observe(fresh, winner.record)
	finish := func(current authoritycutover.Record, change authoritycutover.Change) authoritycutover.Record {
		t.Helper()
		for _, action := range []authoritycutover.Action{authoritycutover.MarkDrained, authoritycutover.ObserveApplied, authoritycutover.Reopen} {
			next, err := fresh.Apply(ctx, current, action, change)
			if err != nil {
				t.Fatalf("finish %s: %v", action, err)
			}
			current = next
		}
		return current
	}
	opened := finish(winner.record, winner.change)
	other := first
	if winner.change == first {
		other = second
	}
	draining, err := fresh.Apply(ctx, opened, authoritycutover.Begin, other)
	if err != nil {
		t.Fatal(err)
	}
	latest := finish(draining, other)
	if latest.Generation != 3 || latest.Phase != authoritycutover.Open || latest.Revision != 9 {
		t.Fatalf("unexpected completed generation: %+v", latest)
	}
	// The pure domain model only remembers the last change. The store must
	// reject historical IDs even after a different cutover completed.
	for _, replay := range []authoritycutover.Change{winner.change, {ID: winner.change.ID, ManifestDigest: other.ManifestDigest, Operator: other.Operator}} {
		if _, err := fresh.Apply(ctx, latest, authoritycutover.Begin, replay); !errors.Is(err, authoritycutover.ErrConflict) {
			t.Fatalf("historical change replay accepted: %v", err)
		}
		observe(fresh, latest)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_changes").Scan(&count); err != nil || count != 2 {
		t.Fatalf("historical replay mutated durable claims: %d %v", count, err)
	}

	// Simulate accidental partial restore by the trusted owner, not an
	// attacker with unrestricted database ownership. A current record
	// whose claim is missing or has a mismatched start generation must not
	// be accepted, and restoring the claim must recover the positive case.
	if _, err := admin.Exec(ctx, "UPDATE public.acp_authority_cutover_changes SET start_generation=1 WHERE change_id=$1", other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Observe(ctx); !errors.Is(err, authoritycutover.ErrInvalid) {
		t.Fatalf("mismatched claim accepted: %v", err)
	}
	if _, err := admin.Exec(ctx, "UPDATE public.acp_authority_cutover_changes SET start_generation=2 WHERE change_id=$1", other.ID); err != nil {
		t.Fatal(err)
	}
	observe(fresh, latest)

	// Duplicate generation claims must be denied even if the current
	// claim and complete revision sequence are individually valid.
	for _, generation := range []int64{1, 2} {
		duplicate := authoritycutover.Change{ID: "duplicate-generation", ManifestDigest: "sha256:" + strings.Repeat("f", 64), Operator: "operator-f"}
		if _, err := admin.Exec(ctx, `INSERT INTO public.acp_authority_cutover_changes
			(change_id,manifest_digest,operator_id,start_generation) VALUES ($1,$2,$3,$4)`,
			duplicate.ID, duplicate.ManifestDigest, duplicate.Operator, generation); err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.Observe(ctx); !errors.Is(err, authoritycutover.ErrInvalid) {
			t.Fatalf("duplicate generation %d accepted: %v", generation, err)
		}
		if _, err := fresh.Apply(ctx, latest, authoritycutover.Begin, authoritycutover.Change{ID: "blocked-duplicate", ManifestDigest: duplicate.ManifestDigest, Operator: duplicate.Operator}); !errors.Is(err, authoritycutover.ErrInvalid) {
			t.Fatalf("duplicate generation %d permitted new change: %v", generation, err)
		}
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_changes").Scan(&count); err != nil || count != 3 {
			t.Fatalf("duplicate generation rejection mutated claims: %d %v", count, err)
		}
		if _, err := admin.Exec(ctx, "DELETE FROM public.acp_authority_cutover_changes WHERE change_id=$1", duplicate.ID); err != nil {
			t.Fatal(err)
		}
		observe(fresh, latest)
	}

	// A non-genesis rollback can still reference a genuine historical claim.
	// Reject it if a later cutover claim survives, even when the old record
	// and its original claim agree byte-for-byte.
	restoreState := func(r authoritycutover.Record) {
		t.Helper()
		tag, err := admin.Exec(ctx, `UPDATE public.acp_authority_cutover_state
			SET generation=$1,revision=$2,phase=$3,change_id=$4,manifest_digest=$5,operator_id=$6 WHERE id=1`,
			r.Generation, r.Revision, string(r.Phase), r.Change.ID, r.Change.ManifestDigest, r.Change.Operator)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("restore fixture: %v", err)
		}
	}
	// Restore VERIFYING from the same completed change. Its generation and
	// change claim are genuine; only the state revision and phase are older.
	oldRevision := latest
	oldRevision.Phase = authoritycutover.Verifying
	oldRevision.Revision--
	restoreState(oldRevision)
	if _, err := fresh.Observe(ctx); !errors.Is(err, authoritycutover.ErrInvalid) {
		t.Errorf("same-generation rollback accepted: %v", err)
	}
	if _, err := fresh.Apply(ctx, oldRevision, authoritycutover.Reopen, other); !errors.Is(err, authoritycutover.ErrInvalid) {
		t.Errorf("same-generation reopen accepted: %v", err)
	}
	restoreState(latest)
	observe(fresh, latest)
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_transitions").Scan(&transitionCount); err != nil || transitionCount != 8 {
		t.Errorf("expected eight durable transitions after two cutovers: %d %v", transitionCount, err)
	}

	// A continuous revision sequence is insufficient if an older row no
	// longer agrees with the durable claim. Keep the latest row intact.
	for _, revision := range []int64{3, 5, 8} {
		var originalOperator string
		if err := admin.QueryRow(ctx, "SELECT operator_id FROM public.acp_authority_cutover_transitions WHERE revision=$1", revision).Scan(&originalOperator); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, "UPDATE public.acp_authority_cutover_transitions SET operator_id='corrupt' WHERE revision=$1", revision); err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.Observe(ctx); !errors.Is(err, authoritycutover.ErrInvalid) {
			t.Fatalf("inconsistent historical revision %d accepted: %v", revision, err)
		}
		blocked := authoritycutover.Change{ID: "blocked-history-corruption", ManifestDigest: other.ManifestDigest, Operator: other.Operator}
		if _, err := fresh.Apply(ctx, latest, authoritycutover.Begin, blocked); !errors.Is(err, authoritycutover.ErrInvalid) {
			t.Fatalf("inconsistent historical revision %d permitted new change: %v", revision, err)
		}
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_changes").Scan(&count); err != nil || count != 2 {
			t.Fatalf("history corruption rejection mutated claims: %d %v", count, err)
		}
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_transitions").Scan(&transitionCount); err != nil || transitionCount != 8 {
			t.Fatalf("history corruption rejection mutated transitions: %d %v", transitionCount, err)
		}
		if _, err := admin.Exec(ctx, "UPDATE public.acp_authority_cutover_transitions SET operator_id=$1 WHERE revision=$2", originalOperator, revision); err != nil {
			t.Fatal(err)
		}
		observe(fresh, latest)
	}

	// Phase order must agree with the revision even when generation and
	// change identity remain valid. Each pair shares a claim generation.
	for _, probe := range []struct {
		revision int64
		original string
		corrupt  string
	}{
		{2, "DRAINING", "CLOSED"},
		{3, "CLOSED", "DRAINING"},
		{4, "VERIFYING", "OPEN"},
		{5, "OPEN", "VERIFYING"},
		{6, "DRAINING", "CLOSED"},
		{7, "CLOSED", "DRAINING"},
		{8, "VERIFYING", "OPEN"},
	} {
		if _, err := admin.Exec(ctx, "UPDATE public.acp_authority_cutover_transitions SET phase=$1 WHERE revision=$2", probe.corrupt, probe.revision); err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.Observe(ctx); !errors.Is(err, authoritycutover.ErrInvalid) {
			t.Fatalf("historical phase order at revision %d accepted: %v", probe.revision, err)
		}
		blocked := authoritycutover.Change{ID: "blocked-phase-order", ManifestDigest: other.ManifestDigest, Operator: other.Operator}
		if _, err := fresh.Apply(ctx, latest, authoritycutover.Begin, blocked); !errors.Is(err, authoritycutover.ErrInvalid) {
			t.Fatalf("historical phase order at revision %d permitted new change: %v", probe.revision, err)
		}
		if _, err := admin.Exec(ctx, "UPDATE public.acp_authority_cutover_transitions SET phase=$1 WHERE revision=$2", probe.original, probe.revision); err != nil {
			t.Fatal(err)
		}
		observe(fresh, latest)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_changes").Scan(&count); err != nil || count != 2 {
		t.Fatalf("phase order rejection mutated claims: %d %v", count, err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_transitions").Scan(&transitionCount); err != nil || transitionCount != 8 {
		t.Fatalf("phase order rejection mutated transitions: %d %v", transitionCount, err)
	}

	// Keep the latest revision and claim intact, but remove a historical
	// transition. A partial restore must not silently erase audit history.
	exec("DELETE FROM public.acp_authority_cutover_transitions WHERE revision=3")
	if _, err := fresh.Observe(ctx); !errors.Is(err, authoritycutover.ErrInvalid) {
		t.Fatalf("missing intermediate revision accepted: %v", err)
	}
	gapChange := authoritycutover.Change{ID: "change-with-history-gap", ManifestDigest: "sha256:" + strings.Repeat("e", 64), Operator: "operator-e"}
	if _, err := fresh.Apply(ctx, latest, authoritycutover.Begin, gapChange); !errors.Is(err, authoritycutover.ErrInvalid) {
		t.Fatalf("history gap permitted a new change: %v", err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_transitions").Scan(&transitionCount); err != nil || transitionCount != 7 {
		t.Fatalf("history gap rejection mutated transitions: %d %v", transitionCount, err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_changes").Scan(&count); err != nil || count != 2 {
		t.Fatalf("history gap rejection mutated claims: %d %v", count, err)
	}
	// Restore only the missing original CLOSED record; no state update.
	if _, err := admin.Exec(ctx, `INSERT INTO public.acp_authority_cutover_transitions
		(revision,generation,phase,change_id,manifest_digest,operator_id)
		VALUES (3,1,'CLOSED',$1,$2,$3)`, winner.change.ID, winner.change.ManifestDigest, winner.change.Operator); err != nil {
		t.Fatal(err)
	}
	observe(fresh, latest)

	restoreState(opened)
	if _, err := fresh.Observe(ctx); !errors.Is(err, authoritycutover.ErrInvalid) {
		t.Errorf("old OPEN record with newer surviving claim accepted: %v", err)
	}
	future := authoritycutover.Change{ID: "change-after-rollback", ManifestDigest: "sha256:" + strings.Repeat("d", 64), Operator: "operator-d"}
	if _, err := fresh.Apply(ctx, opened, authoritycutover.Begin, future); !errors.Is(err, authoritycutover.ErrInvalid) {
		t.Errorf("old OPEN record permitted a new change: %v", err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_changes").Scan(&count); err != nil || count != 2 {
		t.Fatalf("non-genesis rollback mutated history: %d %v", count, err)
	}
	restoreState(latest)
	observe(fresh, latest)

	// A state-only restore to genesis must not silently reopen a database
	// whose durable change ledger still proves prior cutovers occurred.
	exec("UPDATE public.acp_authority_cutover_state SET generation=1,revision=1,phase='OPEN',change_id='',manifest_digest='',operator_id='' WHERE id=1")
	if _, err := fresh.Observe(ctx); !errors.Is(err, authoritycutover.ErrInvalid) {
		t.Errorf("genesis with existing change history was accepted: %v", err)
	}
	third := authoritycutover.Change{ID: "change-c", ManifestDigest: "sha256:" + strings.Repeat("c", 64), Operator: "operator-c"}
	if _, err := fresh.Apply(ctx, initial, authoritycutover.Begin, third); !errors.Is(err, authoritycutover.ErrInvalid) {
		t.Errorf("partial restore permitted a new change: %v", err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.acp_authority_cutover_changes").Scan(&count); err != nil || count != 2 {
		t.Fatalf("partial restore mutated history: %d %v", count, err)
	}
}
