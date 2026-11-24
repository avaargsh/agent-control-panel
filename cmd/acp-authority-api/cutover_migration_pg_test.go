package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/authoritycutover"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Exercise the actual opt-in migration rather than reproducing its DDL in a fixture.
func TestAuthorityCutoverPostgresMigration(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, database := isolatedAuthorityRoleTestDatabase(t, ctx, dsn)
	defer admin.Close(context.Background())

	sql, err := os.ReadFile("../../migrations/authority-cutover/0001_state_ledger.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, string(sql)); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = database
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := authoritycutover.NewPostgresStore(pool)
	initial := authoritycutover.Record{Generation: 1, Revision: 1, Phase: authoritycutover.Open}
	observe := func(want authoritycutover.Record) {
		t.Helper()
		got, err := store.Observe(ctx)
		if err != nil || got != want {
			t.Fatalf("observe: got=%+v want=%+v err=%v", got, want, err)
		}
	}
	observe(initial)
	change := authoritycutover.Change{ID: "migration-a", ManifestDigest: "sha256:" + strings.Repeat("a", 64), Operator: "operator-a"}
	current := initial
	for _, action := range []authoritycutover.Action{authoritycutover.Begin, authoritycutover.MarkDrained, authoritycutover.ObserveApplied, authoritycutover.Reopen} {
		next, err := store.Apply(ctx, current, action, change)
		if err != nil {
			t.Fatalf("apply %s: %v", action, err)
		}
		observe(next)
		current = next
	}
	if current.Generation != 2 || current.Revision != 5 || current.Phase != authoritycutover.Open {
		t.Fatalf("unexpected completed cutover: %+v", current)
	}

	deny := func(code, query string, args ...any) {
		t.Helper()
		_, err := admin.Exec(ctx, query, args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != code {
			t.Fatalf("expected SQLSTATE %s for %s: %v", code, query, err)
		}
		observe(current)
	}
	deny("23505", "INSERT INTO public.acp_authority_cutover_changes VALUES ('duplicate-generation',$1,'operator-b',1)", change.ManifestDigest)
	deny("23514", "INSERT INTO public.acp_authority_cutover_changes VALUES ('bad-digest','invalid','operator-b',2)")
	deny("23514", "UPDATE public.acp_authority_cutover_state SET phase='VERIFYING' WHERE id=1")
	deny("23514", "UPDATE public.acp_authority_cutover_transitions SET phase='DRAINING' WHERE revision=3")
	deny("23503", "UPDATE public.acp_authority_cutover_transitions SET operator_id='forged' WHERE revision=3")
	deny("23503", "UPDATE public.acp_authority_cutover_transitions SET manifest_digest=$1 WHERE revision=3", "sha256:"+strings.Repeat("b", 64))

	// The bootstrap is intentionally not replayable over existing state.
	if _, err := admin.Exec(ctx, string(sql)); err == nil {
		t.Fatal("bootstrap unexpectedly replayed")
	}
	if _, err := admin.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	observe(current)
	var claims, transitions int
	if err := admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM public.acp_authority_cutover_changes),(SELECT count(*) FROM public.acp_authority_cutover_transitions)").Scan(&claims, &transitions); err != nil || claims != 1 || transitions != 4 {
		t.Fatalf("unexpected history counts: %d %d %v", claims, transitions, err)
	}
}
