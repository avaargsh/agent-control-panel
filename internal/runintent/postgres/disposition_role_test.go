package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This PostgreSQL 16 role test uses an independent physical LOGIN connection
// to a disposable schema. It does not provision production IAM, tenant RLS,
// broker origin binding, TLS or least-privilege deployment credentials.
func TestDispositionV3RestrictedDatabaseRole(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	schema := pool.Config().ConnConfig.RuntimeParams["search_path"]
	role := "acp_dlq_worker_" + strconv.FormatInt(time.Now().UnixNano(), 10)

	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("create test-only role password: %v", err)
	}
	password := fmt.Sprintf("%x", secret)
	if _, err := pool.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+password+"'"); err != nil {
		t.Fatalf("create restricted test role: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DROP OWNED BY "+role); err != nil {
			t.Errorf("revoke worker grants: %v", err)
			return
		}
		if _, err := pool.Exec(context.Background(), "DROP ROLE "+role); err != nil {
			t.Errorf("drop restricted test role: %v", err)
		}
	})
	for _, grant := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT SELECT,INSERT ON inbox_dlq_dispositions TO " + role,
		"GRANT UPDATE (publish_started,published,published_at) ON inbox_dlq_dispositions TO " + role,
	} {
		if _, err := pool.Exec(ctx, grant); err != nil {
			t.Fatalf("install restricted test grant: %v", err)
		}
	}

	// Tenant B has independent journal evidence on the same shared table.
	// The worker is authenticated for tenant A, never tenant B.
	otherTenantInsert := fmt.Sprintf(
		"INSERT INTO inbox_dlq_dispositions(tenant_id,consumer_name,source_stream,source_consumer,source_sequence,event_id,delivery_sha256,reason,dlq_stream,dlq_subject,evidence) "+
			"VALUES ('tenant-b','consumer-b','stream-b','jetstream-durable-b',43,'00000000-0000-4000-8000-000000000043'::uuid,'%s','INBOX_QUARANTINED','dlq-b','dlq.b.43','{}'::bytea)",
		strings.Repeat("b", 64))
	if _, err := pool.Exec(ctx, otherTenantInsert); err != nil {
		t.Fatalf("seed tenant-B journal evidence: %v", err)
	}

	// NON-PRODUCTION POLICY PROOF: role ownership is trusted because the
	// disposable test migrator explicitly provisions the LOGIN below. The
	// external broker/tenant authority and forward versioned migration are
	// NOT implemented by this test. Never use an app-settable tenant GUC
	// as the RLS authority.
	for _, statement := range []string{
		"CREATE POLICY acp_test_tenant_a_dlq_role ON inbox_dlq_dispositions FOR ALL TO " + role +
			" USING (tenant_id = 'tenant-a') WITH CHECK (tenant_id = 'tenant-a')",
		"ALTER TABLE inbox_dlq_dispositions ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE inbox_dlq_dispositions FORCE ROW LEVEL SECURITY",
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("install disposable tenant-scoped RLS: %v", err)
		}
	}
	var rlsEnabled, rlsForced, roleIsSuper, roleBypass bool
	if err := pool.QueryRow(ctx,
		"SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = to_regclass('inbox_dlq_dispositions')").
		Scan(&rlsEnabled, &rlsForced); err != nil {
		t.Fatalf("inspect test RLS catalog: %v", err)
	}
	if err := pool.QueryRow(ctx,
		"SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1", role).
		Scan(&roleIsSuper, &roleBypass); err != nil {
		t.Fatalf("inspect test worker privileges: %v", err)
	}
	if !rlsEnabled || !rlsForced || roleIsSuper || roleBypass {
		t.Fatalf("disposable RLS proof has weak role/policy settings: enabled=%v forced=%v super=%v bypass=%v",
			rlsEnabled, rlsForced, roleIsSuper, roleBypass)
	}

	workerConfig := pool.Config().ConnConfig.Copy()
	workerConfig.User = role
	workerConfig.Password = password
	workerConn, err := pgx.ConnectConfig(ctx, workerConfig)
	if err != nil {
		t.Fatalf("open independent worker LOGIN connection: %v", err)
	}
	t.Cleanup(func() { _ = workerConn.Close(context.Background()) })

	asWorker := func(sql string) error {
		t.Helper()
		tx, err := workerConn.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(context.Background())
		var current string
		if err := tx.QueryRow(ctx, "SELECT current_user").Scan(&current); err != nil {
			return err
		}
		if current != role {
			return fmt.Errorf("wrong worker database principal: %s", current)
		}
		var sessionUser string
		if err := tx.QueryRow(ctx, "SELECT session_user").Scan(&sessionUser); err != nil {
			return err
		}
		if sessionUser != role {
			return fmt.Errorf("worker is not independently authenticated: session_user=%s current_user=%s", sessionUser, current)
		}
		if _, err := tx.Exec(ctx, sql); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	insert := fmt.Sprintf(
		"INSERT INTO inbox_dlq_dispositions(tenant_id,consumer_name,source_stream,source_consumer,source_sequence,event_id,delivery_sha256,reason,dlq_stream,dlq_subject,evidence) "+
			"VALUES ('tenant-a','consumer-a','stream-a','jetstream-durable-a',42,'00000000-0000-4000-8000-000000000042'::uuid,'%s','EVENT_ID_CONFLICT','dlq-a','dlq.a.42','{}'::bytea)",
		strings.Repeat("a", 64))
	if err := asWorker(insert); err != nil {
		t.Fatalf("restricted role could not insert journal identity: %v", err)
	}
	if err := asWorker("UPDATE inbox_dlq_dispositions SET publish_started=true"); err != nil {
		t.Fatalf("restricted role could not set durable attempt: %v", err)
	}
	if err := asWorker("UPDATE inbox_dlq_dispositions SET published=true,published_at=clock_timestamp()"); err != nil {
		t.Fatalf("restricted role could not confirm disposition: %v", err)
	}

	// Test-only independently authenticated tenant-A worker must not read tenant-B
	// evidence, publish its dispositions or create tenant-B entries.
	t.Run("tenant-B SELECT is invisible", func(t *testing.T) {
		var count int
		if err := workerConn.QueryRow(ctx,
			"SELECT count(*) FROM inbox_dlq_dispositions WHERE tenant_id='tenant-b'").Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("tenant-A LOGIN read %d tenant-B journal rows", count)
		}
	})
	t.Run("tenant-B UPDATE is denied", func(t *testing.T) {
		tag, err := workerConn.Exec(ctx,
			"UPDATE inbox_dlq_dispositions SET publish_started=true WHERE tenant_id='tenant-b'")
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("tenant-A LOGIN could mutate tenant-B journal: affected=%d err=%v", tag.RowsAffected(), err)
		}
		var began bool
		if err := pool.QueryRow(ctx,
			"SELECT publish_started FROM inbox_dlq_dispositions WHERE tenant_id='tenant-b'").Scan(&began); err != nil {
			t.Fatal(err)
		}
		if began {
			t.Error("tenant-B publication state changed under tenant-A credentials")
		}
	})
	t.Run("tenant-B INSERT is rejected", func(t *testing.T) {
		other := fmt.Sprintf(
			"INSERT INTO inbox_dlq_dispositions(tenant_id,consumer_name,source_stream,source_consumer,source_sequence,event_id,delivery_sha256,reason,dlq_stream,dlq_subject,evidence) "+
				"VALUES ('tenant-b','consumer-b','stream-b','jetstream-durable-b',44,'00000000-0000-4000-8000-000000000044'::uuid,'%s','INBOX_QUARANTINED','dlq-b','dlq.b.44','{}'::bytea)",
			strings.Repeat("b", 64))
		_, err := workerConn.Exec(ctx, other)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("tenant-A LOGIN can forge tenant-B evidence: %v, want SQLSTATE 42501", err)
		}
	})

	for _, tc := range []struct {
		name     string
		sql      string
		wantCode string
	}{
		{"edit immutable evidence", "UPDATE inbox_dlq_dispositions SET evidence='tampered'::bytea", "42501"},
		{"edit tenant scope", "UPDATE inbox_dlq_dispositions SET tenant_id='tenant-b'", "42501"},
		{"delete", "DELETE FROM inbox_dlq_dispositions", "42501"},
		{"read migration checksum ledger", "SELECT checksum FROM schema_migrations", "42501"},
		{"read RunIntent", "SELECT count(*) FROM run_intents", "42501"},
		{"read RunIntent Outbox", "SELECT count(*) FROM outbox_events", "42501"},
		{"truncate", "TRUNCATE inbox_dlq_dispositions", "42501"},
		{"disable integrity trigger", "ALTER TABLE inbox_dlq_dispositions DISABLE TRIGGER inbox_dlq_no_unsafe_update_delete", "42501"},
		{"rollback publication", "UPDATE inbox_dlq_dispositions SET published=false,published_at=NULL", "P0001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := asWorker(tc.sql)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != tc.wantCode {
				t.Fatalf("unexpected role/guard outcome for %s: %v, want SQLSTATE %s", tc.name, err, tc.wantCode)
			}
		})
	}
}
