package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// These cases must fail closed on the actual PostgreSQL catalog, regardless
// of the checksum-pinned migration file's unchanged historical digest.
func TestCanonicalDLQV3RejectsCriticalCatalogDrift(t *testing.T) {
	cases := []struct {
		name       string
		statements []string
	}{
		{"digest CHECK removed", []string{
			"ALTER TABLE inbox_dlq_dispositions DROP CONSTRAINT inbox_dlq_dispositions_delivery_sha256_check",
		}},
		{"reason CHECK bypassed", []string{
			"ALTER TABLE inbox_dlq_dispositions DROP CONSTRAINT inbox_dlq_dispositions_reason_check",
			"ALTER TABLE inbox_dlq_dispositions ADD CONSTRAINT inbox_dlq_dispositions_reason_check CHECK (TRUE)",
		}},
		{"journal converted to UNLOGGED", []string{
			"ALTER TABLE inbox_dlq_dispositions SET UNLOGGED",
		}},
		{"event ID NOT NULL removed", []string{
			"ALTER TABLE inbox_dlq_dispositions ALTER COLUMN event_id DROP NOT NULL",
		}},
		{"PUBLIC SELECT privilege leaked", []string{
			"GRANT SELECT ON inbox_dlq_dispositions TO PUBLIC",
		}},
		{"PUBLIC guard EXECUTE privilege leaked", []string{
			"GRANT EXECUTE ON FUNCTION reject_inbox_dlq_disposition_mutation() TO PUBLIC",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pool := testRepository(t)
			for _, statement := range tc.statements {
				if _, err := pool.Exec(context.Background(), statement, pgx.QueryExecModeSimpleProtocol); err != nil {
					t.Fatalf("inject %s: %v", tc.name, err)
				}
			}
			if err := Migrate(context.Background(), pool); !errors.Is(err, ErrSchemaDrift) {
				t.Fatalf("critical v3 catalog drift accepted (%s): %v", tc.name, err)
			}
		})
	}
}
