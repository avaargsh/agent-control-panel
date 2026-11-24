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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Independent LOGINs exercise table ACLs. Do not use SET ROLE to impersonate
// either application principal; only the administrative setup uses SET ROLE.
func TestAuthorityCutoverPostgresLedgerACL(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	root, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var roles []string
	// Register before the disposable DB helper: drop DB before cluster roles.
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
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
	create := func(name, options string) {
		t.Helper()
		exec("CREATE ROLE " + pgx.Identifier{name}.Sanitize() + " " + options)
		roles = append(roles, name)
	}
	const owner = "acp_cutover_schema_owner"
	const writerGroup = "acp_cutover_coordinator"
	const readerGroup = "acp_cutover_observer"
	for _, role := range []string{owner, writerGroup, readerGroup} {
		create(role, "NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS")
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	login := func(prefix, group string) (*pgxpool.Pool, string) {
		t.Helper()
		name := prefix + suffix
		var secret [24]byte
		if _, err := rand.Read(secret[:]); err != nil {
			t.Fatal(err)
		}
		password := fmt.Sprintf("%x", secret)
		create(name, "LOGIN INHERIT NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'")
		exec("GRANT " + group + " TO " + pgx.Identifier{name}.Sanitize())
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.Database = database
		cfg.ConnConfig.User = name
		cfg.ConnConfig.Password = password
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		var actual string
		if err := pool.QueryRow(ctx, "SELECT session_user").Scan(&actual); err != nil || actual != name {
			t.Fatalf("independent login: %q %v", actual, err)
		}
		return pool, name
	}
	exec("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
	exec("GRANT USAGE ON SCHEMA public TO " + owner + ", " + writerGroup + ", " + readerGroup)
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
	writer, writerName := login("acp_cutover_writer_", writerGroup)
	reader, readerName := login("acp_cutover_reader_", readerGroup)
	if writerName == readerName {
		t.Fatal("writer and observer must authenticate independently")
	}
	coordinator := authoritycutover.NewPostgresStore(writer)
	observer := authoritycutover.NewPostgresStore(reader)
	initial := authoritycutover.Record{Generation: 1, Revision: 1, Phase: authoritycutover.Open}
	change := authoritycutover.Change{ID: "acl-a", ManifestDigest: "sha256:" + strings.Repeat("a", 64), Operator: "operator-a"}
	current := initial
	for _, action := range []authoritycutover.Action{authoritycutover.Begin, authoritycutover.MarkDrained, authoritycutover.ObserveApplied, authoritycutover.Reopen} {
		current, err = coordinator.Apply(ctx, current, action, change)
		if err != nil {
			t.Fatalf("coordinator apply %s: %v", action, err)
		}
		if got, err := observer.Observe(ctx); err != nil || got != current {
			t.Fatalf("observer read: %+v %v", got, err)
		}
	}
	deny := func(pool *pgxpool.Pool, query string) {
		t.Helper()
		_, err := pool.Exec(ctx, query)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("expected permission denied for %s: %v", query, err)
		}
	}
	for _, pool := range []*pgxpool.Pool{writer, reader} {
		for _, table := range []string{"state", "changes", "transitions"} {
			relation := "public.acp_authority_cutover_" + table
			deny(pool, "DELETE FROM "+relation)
			deny(pool, "TRUNCATE "+relation)
			deny(pool, "ALTER TABLE "+relation+" ADD COLUMN forbidden integer")
		}
		deny(pool, "UPDATE public.acp_authority_cutover_changes SET operator_id='forged'")
		deny(pool, "UPDATE public.acp_authority_cutover_transitions SET operator_id='forged'")
		deny(pool, "CREATE TABLE public.cutover_forbidden (id integer)")
		deny(pool, "CREATE TEMP TABLE cutover_forbidden (id integer)")
		deny(pool, "SET ROLE "+owner)
		deny(pool, "UPDATE public.acp_authority_cutover_state SET id=1")
		deny(pool, "INSERT INTO public.acp_authority_cutover_state SELECT * FROM public.acp_authority_cutover_state")
	}
	deny(reader, "UPDATE public.acp_authority_cutover_state SET phase='OPEN'")
	deny(reader, "INSERT INTO public.acp_authority_cutover_changes (change_id,manifest_digest,operator_id,start_generation) SELECT change_id,manifest_digest,operator_id,start_generation FROM public.acp_authority_cutover_changes")
	deny(reader, "INSERT INTO public.acp_authority_cutover_transitions (revision,generation,phase,change_id,manifest_digest,operator_id) SELECT revision,generation,phase,change_id,manifest_digest,operator_id FROM public.acp_authority_cutover_transitions")
	deny(reader, "SET ROLE "+writerGroup)
	got, err := observer.Observe(ctx)
	if err != nil || got != current || current.Revision != 5 {
		t.Fatalf("denied writes changed state: %+v %v", got, err)
	}
}
