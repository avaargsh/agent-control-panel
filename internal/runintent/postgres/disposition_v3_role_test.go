package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestMigrationV3RejectsPublicPrivilegeDrift(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"table SELECT grant", "GRANT SELECT ON dlq_dispositions TO PUBLIC"},
		{"table TRUNCATE grant", "GRANT TRUNCATE ON dlq_dispositions TO PUBLIC"},
		{"guard function EXECUTE grant", "GRANT EXECUTE ON FUNCTION reject_dlq_disposition_mutation() TO PUBLIC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			if _, err := pool.Exec(context.Background(), tc.sql); err != nil {
				t.Fatalf("inject privilege drift: %v", err)
			}
			if err := Migrate(context.Background(), pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("public privilege drift accepted (%s): %v", tc.name, err)
			}
		})
	}
}

func TestMigrationV3IsolatedColumnScopedDatabaseWriter(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	schema := pool.Config().ConnConfig.RuntimeParams["search_path"]
	role := "acp_dlq_v3_writer_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if _, err := pool.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DROP OWNED BY "+role); err != nil {
			t.Errorf("revoke test role grants: %v", err)
			return
		}
		if _, err := pool.Exec(context.Background(), "DROP ROLE "+role); err != nil {
			t.Errorf("delete test role: %v", err)
		}
	})
	for _, sql := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT SELECT ON dlq_dispositions TO " + role,
		"GRANT INSERT (tenant_id,consumer_name,source_stream,source_consumer,source_sequence,delivery_sha256,reason,dlq_stream,dlq_subject,evidence) ON dlq_dispositions TO " + role,
		"GRANT UPDATE (publish_started,published,published_at) ON dlq_dispositions TO " + role,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatalf("grant column-scoped settlement permissions: %v", err)
		}
	}
	execAsRole := func(sql string) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sql); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	insert := fmt.Sprintf(`INSERT INTO dlq_dispositions(
		tenant_id,consumer_name,source_stream,source_consumer,source_sequence,
		delivery_sha256,reason,dlq_stream,dlq_subject,evidence)
		VALUES('tenant-a','billing-consumer','source','consumer',1,
		'%s','EVENT_ID_CONFLICT','dlq','dlq.subject.1','{}'::bytea)`, 
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err := execAsRole(insert); err != nil {
		t.Fatalf("limited writer cannot persist immutable event: %v", err)
	}
	if err := execAsRole("UPDATE dlq_dispositions SET publish_started=true"); err != nil {
		t.Fatalf("limited writer cannot persist publish attempt: %v", err)
	}
	if err := execAsRole("UPDATE dlq_dispositions SET published=true,published_at=clock_timestamp()"); err != nil {
		t.Fatalf("limited writer cannot confirm publication: %v", err)
	}
	for _, tc := range []struct {
		name string
		sql string
		code string
	}{
		{"insert forged state", "INSERT INTO dlq_dispositions(tenant_id,consumer_name,source_stream,source_consumer,source_sequence,delivery_sha256,reason,dlq_stream,dlq_subject,evidence,publish_started,published,published_at) VALUES('tenant-a','billing-consumer','source','consumer',2,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','EVENT_ID_CONFLICT','dlq','dlq.subject.2','{}'::bytea,true,true,clock_timestamp())", "42501"},
		{"edit evidence", "UPDATE dlq_dispositions SET evidence='changed'::bytea", "42501"},
		{"edit tenant", "UPDATE dlq_dispositions SET tenant_id='tenant-b'", "42501"},
		{"delete record", "DELETE FROM dlq_dispositions", "42501"},
		{"truncate journal", "TRUNCATE dlq_dispositions", "42501"},
		{"drop guard trigger", "DROP TRIGGER dlq_disposition_no_truncate ON dlq_dispositions", "42501"},
		{"rollback status", "UPDATE dlq_dispositions SET published=false,published_at=NULL", "P0001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := execAsRole(tc.sql)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != tc.code {
				t.Fatalf("invalid privilege/guard behavior (%s): got %v, need SQLSTATE %s", tc.name, err, tc.code)
			}
		})
	}
}
