package agentd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// An 0015 mapping contains only a LOGIN name. It cannot establish which
// principal originally owned that name if an administrator dropped and
// recreated the role before applying 0016. Automatic OID backfill would
// silently bless the new principal with the previous tenant's authority.
//
// This is a real isolated PostgreSQL DATABASE upgrade from historical 0015,
// not a clean schema test or a mocked SQL parser. It never changes the
// shared AgentD CI database used by the other tests in this package.
func TestAgentDEvidenceReaderOIDUpgradeRequiresExplicitReenrollment(t *testing.T) {
	dsn := os.Getenv("SANDBOX_JOURNAL_TEST_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL with CREATE DATABASE/ROLE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	dbName := fmt.Sprintf("agentd_upgrade_%d", time.Now().UnixNano())
	loginName := fmt.Sprintf("agentd_legacy_login_%d", time.Now().UnixNano())
	qDB, qLogin := pgx.Identifier{dbName}.Sanitize(), pgx.Identifier{loginName}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+qDB); err != nil {
		_ = admin.Close(context.Background())
		t.Fatalf("dedicated upgrade database could not be created: %v", err)
	}
	var upgradePool *pgxpool.Pool
	t.Cleanup(func() {
		if upgradePool != nil {
			upgradePool.Close()
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+qDB+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated upgrade database: %v", err)
		}
		if _, err := admin.Exec(cleanupCtx, "DROP ROLE IF EXISTS "+qLogin); err != nil {
			t.Errorf("drop isolated test LOGIN: %v", err)
		}
		_ = admin.Close(context.Background())
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = dbName
	upgradePool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	apply := func(filename string) error {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("..", "migrations", filename))
		if err != nil {
			t.Fatal(err)
		}
		_, err = upgradePool.Exec(ctx, string(raw))
		return err
	}
	for _, filename := range []string{
		"0013_agentd_attempt_terminal.sql",
		"0014_agentd_inspect_events.sql",
		"0015_agentd_evidence_reader_rls.sql",
	} {
		if err := apply(filename); err != nil {
			t.Fatalf("historical schema %s: %v", filename, err)
		}
	}
	if _, err := admin.Exec(ctx, "CREATE ROLE "+qLogin+" LOGIN NOSUPERUSER NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	var oldOID, replacementOID uint32
	if err := admin.QueryRow(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1", loginName).Scan(&oldOID); err != nil {
		t.Fatal(err)
	}
	if _, err := upgradePool.Exec(ctx,
		"INSERT INTO public.sandbox_agentd_evidence_reader_tenants(login_role,tenant_id) VALUES ($1,$2)",
		loginName, "tenant-old"); err != nil {
		t.Fatal(err)
	}
	// Old authorization is a *name-only* mapping, so recreation before the
	// upgrade destroys all available evidence of original principal identity.
	if _, err := admin.Exec(ctx, "DROP ROLE "+qLogin); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE ROLE "+qLogin+" LOGIN NOSUPERUSER NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1", loginName).Scan(&replacementOID); err != nil {
		t.Fatal(err)
	}
	if replacementOID == oldOID {
		t.Fatal("test did not actually recreate the LOGIN with a different role OID")
	}
	// RED against the former 0016: it UPDATEs from pg_roles and silently
	// assigns the NEW principal's OID to tenant-old without owner reapproval.
	if err := apply("0016_agentd_reader_login_oid_fence.sql"); err == nil {
		t.Fatal("unauthenticated legacy LOGIN mapping automatically acquired a new role OID")
	}
	var columnCount int
	if err := upgradePool.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_attribute a
		WHERE a.attrelid='public.sandbox_agentd_evidence_reader_tenants'::regclass
		  AND a.attname='login_oid' AND NOT a.attisdropped`).Scan(&columnCount); err != nil || columnCount != 0 {
		t.Fatalf("failed upgrade partially modified the durable schema: columns=%d err=%v", columnCount, err)
	}
	// A trusted owner explicitly revokes the unverifiable old mapping.
	if _, err := upgradePool.Exec(ctx,
		"DELETE FROM public.sandbox_agentd_evidence_reader_tenants WHERE login_role=$1", loginName); err != nil {
		t.Fatal(err)
	}
	if err := apply("0016_agentd_reader_login_oid_fence.sql"); err != nil {
		t.Fatalf("explicitly revoked legacy mapping prevented safe upgrade: %v", err)
	}
	var rows int
	if err := upgradePool.QueryRow(ctx,
		"SELECT count(*) FROM public.sandbox_agentd_evidence_reader_tenants WHERE login_role=$1",
		loginName).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("new LOGIN inherited old tenant without re-enrollment: rows=%d err=%v", rows, err)
	}
	// Only a fresh, intentional owner-managed mapping can grant a tenant.
	tag, err := upgradePool.Exec(ctx,
		`INSERT INTO public.sandbox_agentd_evidence_reader_tenants(login_role,login_oid,tenant_id)
		  SELECT rolname,oid,$2 FROM pg_catalog.pg_roles WHERE rolname=$1 AND rolcanlogin`,
		loginName, "tenant-new")
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("explicit owner re-enrollment failed: rows=%d err=%v", tag.RowsAffected(), err)
	}
	var boundOID uint32
	var tenant string
	if err := upgradePool.QueryRow(ctx,
		"SELECT login_oid,tenant_id FROM public.sandbox_agentd_evidence_reader_tenants WHERE login_role=$1",
		loginName).Scan(&boundOID, &tenant); err != nil || boundOID != replacementOID || tenant != "tenant-new" {
		t.Fatalf("fresh enrollment has wrong authenticated identity: oid=%d tenant=%q err=%v", boundOID, tenant, err)
	}
	// Historical 0015 and 0016 must remain intact. A separate forward-only
	// migration closes PostgreSQL's PUBLIC TEMP privilege in the isolated
	// database, including an actual 0015 -> 0016 -> 0017 upgrade path.
	if _, err := upgradePool.Exec(ctx, "GRANT TEMPORARY ON DATABASE "+qDB+" TO PUBLIC"); err != nil {
		t.Fatal(err)
	}
	var tempAllowed bool
	if err := upgradePool.QueryRow(ctx,
		"SELECT has_database_privilege($1::name, current_database(), 'TEMP')", loginName).
		Scan(&tempAllowed); err != nil || !tempAllowed {
		t.Fatalf("upgrade fixture lacks pre-0017 PUBLIC TEMP privilege: allowed=%v err=%v", tempAllowed, err)
	}
	if err := apply("0017_agentd_reader_database_temp_fence.sql"); err != nil {
		t.Fatalf("forward-only TEMP revocation migration failed: %v", err)
	}
	if err := upgradePool.QueryRow(ctx,
		"SELECT has_database_privilege($1::name, current_database(), 'TEMP')", loginName).
		Scan(&tempAllowed); err != nil || tempAllowed {
		t.Fatalf("upgrade still lets reader create TEMP objects: allowed=%v err=%v", tempAllowed, err)
	}
	if err := apply("0017_agentd_reader_database_temp_fence.sql"); err != nil {
		t.Fatalf("forward-only migration replay was not idempotent: %v", err)
	}
}
