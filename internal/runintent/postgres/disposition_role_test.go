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
