package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/migrations"
)

const dlqDispositionV3Name = "0003_dlq_dispositions.sql"

func TestMigrationV3InstallsChecksumPinnedDLQDispositions(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	var name, checksum string
	if err := pool.QueryRow(ctx,
		"SELECT name,checksum FROM schema_migrations WHERE version=3",
	).Scan(&name, &checksum); err != nil {
		t.Fatalf("missing recorded DLQ disposition v3: %v", err)
	}
	source, err := migrations.FS.ReadFile(dlqDispositionV3Name)
	if err != nil {
		t.Fatal(err)
	}
	wantChecksum := fmt.Sprintf("%x", sha256.Sum256(source))
	if name != dlqDispositionV3Name || checksum != wantChecksum {
		t.Fatalf("v3 checksum/name mismatch: got %q/%q want %q/%q", name, checksum, dlqDispositionV3Name, wantChecksum)
	}
	var exists bool
	if err := pool.QueryRow(ctx,
		"SELECT to_regclass('dlq_dispositions') IS NOT NULL",
	).Scan(&exists); err != nil || !exists {
		t.Fatalf("missing installed v3 disposition relation: %v exists=%v", err, exists)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("idempotent v3 migration: %v", err)
	}
}

func TestMigrationV3JournalRejectsMutationAndRollback(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		INSERT INTO dlq_dispositions (
			tenant_id,consumer_name,source_stream,source_consumer,
			source_sequence,delivery_sha256,reason,dlq_stream,dlq_subject,evidence
		) VALUES (
			'tenant-a','billing-consumer','SOURCE','SOURCE_CONSUMER',
			1,$1,'EVENT_ID_CONFLICT','DLQ','dlq.subject.1','\\x7b7d'::bytea
		)
	`, strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("insert new frozen journal intent: %v", err)
	}
	for _, tc := range []struct{ name, sql string }{
		{"evidence changed", "UPDATE dlq_dispositions SET evidence='bad'::bytea"},
		{"tenant changed", "UPDATE dlq_dispositions SET tenant_id='tenant-b'"},
		{"identity changed", "UPDATE dlq_dispositions SET source_sequence=2"},
		{"direct confirmation", "UPDATE dlq_dispositions SET published=true,published_at=clock_timestamp()"},
		{"delete", "DELETE FROM dlq_dispositions"},
		{"truncate", "TRUNCATE dlq_dispositions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, tc.sql); err == nil {
				t.Fatalf("v3 accepted illegal mutation %s", tc.name)
			}
		})
	}
	if _, err := pool.Exec(ctx,
		"UPDATE dlq_dispositions SET publish_started=true"); err != nil {
		t.Fatalf("mark publish-attempt fence: %v", err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE dlq_dispositions SET published=true,published_at=clock_timestamp()"); err != nil {
		t.Fatalf("monotonic publish confirmation: %v", err)
	}
	for _, sql := range []string{
		"UPDATE dlq_dispositions SET publish_started=false",
		"UPDATE dlq_dispositions SET published=false,published_at=NULL",
		"UPDATE dlq_dispositions SET published_at=clock_timestamp() + interval '1 hour'",
	} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatalf("v3 accepted state rollback / timestamp tamper: %s", sql)
		}
	}
}

func TestMigrationV3RejectsCatalogGuardDrift(t *testing.T) {
	cases := []struct {
		name       string
		statements []string
	}{
		{"row guard dropped", []string{"DROP TRIGGER dlq_disposition_no_unsafe_update_delete ON dlq_dispositions"}},
		{"row guard disabled", []string{"ALTER TABLE dlq_dispositions DISABLE TRIGGER dlq_disposition_no_unsafe_update_delete"}},
		{"row guard WHEN false", []string{
			"DROP TRIGGER dlq_disposition_no_unsafe_update_delete ON dlq_dispositions",
			"CREATE TRIGGER dlq_disposition_no_unsafe_update_delete BEFORE UPDATE OR DELETE ON dlq_dispositions FOR EACH ROW WHEN (false) EXECUTE FUNCTION reject_dlq_disposition_mutation()",
		}},
		{"row guard UPDATE OF narrowed", []string{
			"DROP TRIGGER dlq_disposition_no_unsafe_update_delete ON dlq_dispositions",
			"CREATE TRIGGER dlq_disposition_no_unsafe_update_delete BEFORE UPDATE OF published OR DELETE ON dlq_dispositions FOR EACH ROW EXECUTE FUNCTION reject_dlq_disposition_mutation()",
		}},
		{"function replaced", []string{
			"CREATE OR REPLACE FUNCTION reject_dlq_disposition_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$",
		}},
		{"truncate guard removed", []string{"DROP TRIGGER dlq_disposition_no_truncate ON dlq_dispositions"}},
		{"published CHECK TRUE", []string{
			"ALTER TABLE dlq_dispositions DROP CONSTRAINT dlq_published_consistency",
			"ALTER TABLE dlq_dispositions ADD CONSTRAINT dlq_published_consistency CHECK (TRUE)",
		}},
		{"attempt CHECK TRUE", []string{
			"ALTER TABLE dlq_dispositions DROP CONSTRAINT dlq_requires_attempt",
			"ALTER TABLE dlq_dispositions ADD CONSTRAINT dlq_requires_attempt CHECK (TRUE)",
		}},
		{"delivery SHA256 CHECK removed", []string{
			"ALTER TABLE dlq_dispositions DROP CONSTRAINT dlq_dispositions_delivery_sha256_check",
		}},
		{"reason CHECK bypassed", []string{
			"ALTER TABLE dlq_dispositions DROP CONSTRAINT dlq_dispositions_reason_check",
			"ALTER TABLE dlq_dispositions ADD CONSTRAINT dlq_dispositions_reason_check CHECK (TRUE)",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			ctx := context.Background()
			for _, sql := range tc.statements {
				if _, err := pool.Exec(ctx, sql); err != nil {
					t.Fatalf("inject catalog drift: %v", err)
				}
			}
			if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("v3 guard drift accepted (%s): %v", tc.name, err)
			}
		})
	}
}

func TestMigrationV3RejectsOrphanedLedgerAndHistoryTampering(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		"UPDATE schema_migrations SET checksum=$1 WHERE version=3",
		strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("changed v3 checksum accepted: %v", err)
	}
}

func TestMigrationV3RecordedV2UpgradePreservesInbox(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "DROP TABLE dlq_dispositions"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DROP FUNCTION reject_dlq_disposition_mutation()"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version=3"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("v2->v3 migration: %v", err)
	}
	var ok bool
	if err := pool.QueryRow(ctx, `
		SELECT to_regclass('dlq_dispositions') IS NOT NULL AND
		       to_regclass('inbox_events') IS NOT NULL AND
		       (SELECT count(*) FROM schema_migrations)=3
	`).Scan(&ok); err != nil || !ok {
		t.Fatalf("migration lost previous domains: ok=%v err=%v", ok, err)
	}
}

// This test verifies the migration schema only; independently provisioned
// production credentials and grants require a separate acceptance gate.
