package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/migrations"
	"github.com/jackc/pgx/v5"
)

// Production migration contract only. This does NOT exercise a deployed
// broker worker role, signed operator approval or the experimental adapter.
func TestDispositionV3MigrationLedgerAndImmutability(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	source, err := migrations.FS.ReadFile("0003_inbox_dlq_dispositions.sql")
	if err != nil {
		t.Fatal(err)
	}
	var name, checksum string
	if err := pool.QueryRow(ctx,
		"SELECT name,checksum FROM schema_migrations WHERE version=3",
	).Scan(&name, &checksum); err != nil {
		t.Fatal(err)
	}
	wantChecksum := fmt.Sprintf("%x", sha256.Sum256(source))
	if name != "0003_inbox_dlq_dispositions.sql" || checksum != wantChecksum {
		t.Fatalf("unverified v3 migration: name=%q checksum=%q expected=%s", name, checksum, wantChecksum)
	}
	var installed bool
	if err := pool.QueryRow(ctx,
		"SELECT to_regclass('inbox_dlq_dispositions') IS NOT NULL",
	).Scan(&installed); err != nil || !installed {
		t.Fatalf("v3 DLQ journal not installed: %v, %v", installed, err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("idempotent migration validation failed: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO inbox_dlq_dispositions(
			tenant_id,consumer_name,source_stream,source_consumer,source_sequence,event_id,
			delivery_sha256,reason,dlq_stream,dlq_subject,evidence
		) VALUES (
			'tenant-a','consumer-a','stream-a','jetstream-durable-a',42,
			'00000000-0000-4000-8000-000000000042'::uuid,
			$1,'EVENT_ID_CONFLICT','dlq-a','dlq.a.42','{}'::bytea
		)`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, query string }{
		{"identity tamper", "UPDATE inbox_dlq_dispositions SET tenant_id='tenant-other'"},
		{"broker consumer tamper", "UPDATE inbox_dlq_dispositions SET source_consumer='other-durable'"},
		{"payload tamper", "UPDATE inbox_dlq_dispositions SET evidence='tampered'::bytea"},
		{"delete", "DELETE FROM inbox_dlq_dispositions"},
		{"truncate", "TRUNCATE inbox_dlq_dispositions"},
		{"confirm without attempt", "UPDATE inbox_dlq_dispositions SET published=true,published_at=clock_timestamp()"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, tc.query); err == nil {
				t.Fatalf("v3 schema allowed %s", tc.name)
			}
		})
	}
	if _, err := pool.Exec(ctx, "UPDATE inbox_dlq_dispositions SET publish_started=true"); err != nil {
		t.Fatalf("legal publish attempt transition rejected: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE inbox_dlq_dispositions SET published=true,published_at=clock_timestamp()"); err != nil {
		t.Fatalf("legal confirm transition rejected: %v", err)
	}
	for _, tc := range []struct{ name, query string }{
		{"rollback attempt", "UPDATE inbox_dlq_dispositions SET publish_started=false"},
		{"rollback confirmation", "UPDATE inbox_dlq_dispositions SET published=false,published_at=NULL"},
		{"forge confirmation time", "UPDATE inbox_dlq_dispositions SET published_at=clock_timestamp()+interval '1 day'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, tc.query); err == nil {
				t.Fatalf("v3 journal allowed %s", tc.name)
			}
		})
	}
}

func TestDispositionV3MigrationFailsClosedOnCatalogDrift(t *testing.T) {
	cases := []struct {
		name       string
		statements []string
	}{
		{"drop row trigger", []string{"DROP TRIGGER inbox_dlq_no_unsafe_update_delete ON inbox_dlq_dispositions"}},
		{"disable row trigger", []string{"ALTER TABLE inbox_dlq_dispositions DISABLE TRIGGER inbox_dlq_no_unsafe_update_delete"}},
		{"weaken row trigger with WHEN false", []string{
			"DROP TRIGGER inbox_dlq_no_unsafe_update_delete ON inbox_dlq_dispositions",
			"CREATE TRIGGER inbox_dlq_no_unsafe_update_delete BEFORE UPDATE OR DELETE ON inbox_dlq_dispositions FOR EACH ROW WHEN (false) EXECUTE FUNCTION reject_inbox_dlq_disposition_mutation()",
		}},
		{"restrict row trigger UPDATE columns", []string{
			"DROP TRIGGER inbox_dlq_no_unsafe_update_delete ON inbox_dlq_dispositions",
			"CREATE TRIGGER inbox_dlq_no_unsafe_update_delete BEFORE UPDATE OF published OR DELETE ON inbox_dlq_dispositions FOR EACH ROW EXECUTE FUNCTION reject_inbox_dlq_disposition_mutation()",
		}},
		{"replace guard function body", []string{
			"CREATE OR REPLACE FUNCTION reject_inbox_dlq_disposition_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$",
		}},
		{"drop truncate guard", []string{"DROP TRIGGER inbox_dlq_no_truncate ON inbox_dlq_dispositions"}},
		{"same-name CHECK TRUE", []string{
			"ALTER TABLE inbox_dlq_dispositions DROP CONSTRAINT inbox_dlq_requires_attempt",
			"ALTER TABLE inbox_dlq_dispositions ADD CONSTRAINT inbox_dlq_requires_attempt CHECK (TRUE)",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			for _, stmt := range tc.statements {
				if _, err := pool.Exec(context.Background(), stmt, pgx.QueryExecModeSimpleProtocol); err != nil {
					t.Fatal(err)
				}
			}
			if err := Migrate(context.Background(), pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("v3 schema drift accepted: %s, error=%v", tc.name, err)
			}
		})
	}
}

func TestDispositionV3RejectsUnversionedPreexistingJournal(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version=3"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("unversioned existing v3 journal was silently adopted: %v", err)
	}
}

func TestDispositionV3UpgradesRecordedV2AndIsIdempotent(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	dropPrincipalSnapshotMigrationForTest(t, pool)
	if _, err := pool.Exec(ctx, "DROP TABLE inbox_dlq_dispositions"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DROP FUNCTION reject_inbox_dlq_disposition_mutation()"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version=3"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("recorded v2 -> v3 upgrade failed: %v", err)
	}
	var present bool
	if err := pool.QueryRow(ctx, `
		SELECT to_regclass('inbox_dlq_dispositions') IS NOT NULL
		       AND EXISTS(SELECT 1 FROM schema_migrations WHERE version=3)
	`).Scan(&present); err != nil || !present {
		t.Fatalf("additive v3 upgrade did not commit: %v, %v", present, err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("v3 checksum and guard recheck failed: %v", err)
	}
}

func TestDispositionV3LedgerCannotSkipV2(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version=2"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("v3 ledger accepted without v2: %v", err)
	}
}
