package agentd

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A PostgreSQL column-level grant is usable even when the corresponding
// table-wide privilege check is false. Evidence readers must reject both
// foreign column-only SELECT and same-source column-only write rights.
func evidenceReaderColumnCheck(t *testing.T, reader *pgxpool.Pool, tenant string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := reader.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	return verifyEvidenceReaderLogin(ctx, tx, tenant)
}

func TestEvidenceReaderDeniesForeignColumnOnlySelect(t *testing.T) {
	owner := testDatabase(t)
	const tenant = "agentd-column-select-a"
	reader := newEvidenceReaderPool(t, owner, tenant)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var login string
	if err := reader.QueryRow(ctx, "SELECT session_user").Scan(&login); err != nil {
		t.Fatal(err)
	}
	if err := evidenceReaderColumnCheck(t, reader, tenant); err != nil {
		t.Fatalf("baseline dedicated reader rejected: %v", err)
	}

	const relation = "public.agentd_foreign_column_probe"
	if _, err := owner.Exec(ctx, "CREATE TABLE "+relation+" (secret text NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := owner.Exec(context.Background(), "DROP TABLE IF EXISTS "+relation); err != nil {
			t.Errorf("clean up foreign column-only probe: %v", err)
		}
	})
	if _, err := owner.Exec(ctx, "INSERT INTO "+relation+" (secret) VALUES ('unrelated-source-data')"); err != nil {
		t.Fatal(err)
	}
	loginSQL := pgx.Identifier{login}.Sanitize()
	if _, err := owner.Exec(ctx, "GRANT SELECT (secret) ON "+relation+" TO "+loginSQL); err != nil {
		t.Fatal(err)
	}
	// Prove the permission really exposes unrelated data, not merely a
	// metadata row: the same LOGIN can read the foreign column.
	var actual string
	if err := reader.QueryRow(ctx, "SELECT secret FROM "+relation).Scan(&actual); err != nil ||
		actual != "unrelated-source-data" {
		t.Fatalf("did not reproduce live column-only SELECT: value=%q err=%v", actual, err)
	}
	var tableWide, anyColumn bool
	if err := reader.QueryRow(ctx,
		"SELECT has_table_privilege(session_user,$1,'SELECT'), has_any_column_privilege(session_user,$1,'SELECT')",
		relation).Scan(&tableWide, &anyColumn); err != nil || tableWide || !anyColumn {
		t.Fatalf("not a column-only SELECT grant: table=%t column=%t err=%v", tableWide, anyColumn, err)
	}
	if err := evidenceReaderColumnCheck(t, reader, tenant); !errors.Is(err, ErrEvidenceReaderUntrusted) {
		t.Fatalf("foreign-column SELECT accepted by AgentD source reader: %v", err)
	}
	if _, err := owner.Exec(ctx, "REVOKE SELECT (secret) ON "+relation+" FROM "+loginSQL); err != nil {
		t.Fatal(err)
	}
	if err := evidenceReaderColumnCheck(t, reader, tenant); err != nil {
		t.Fatalf("reader not restored after revoking foreign-column access: %v", err)
	}
}

func TestEvidenceReaderDeniesColumnOnlySourceWriteGrant(t *testing.T) {
	owner := testDatabase(t)
	const tenant = "agentd-column-write-a"
	reader := newEvidenceReaderPool(t, owner, tenant)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var login string
	if err := reader.QueryRow(ctx, "SELECT session_user").Scan(&login); err != nil {
		t.Fatal(err)
	}
	if err := evidenceReaderColumnCheck(t, reader, tenant); err != nil {
		t.Fatalf("baseline dedicated reader rejected: %v", err)
	}
	loginSQL := pgx.Identifier{login}.Sanitize()
	const relation = "public.sandbox_agentd_attempts"
	if _, err := owner.Exec(ctx, fmt.Sprintf("GRANT UPDATE (status) ON %s TO %s", relation, loginSQL)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := owner.Exec(context.Background(),
			"REVOKE UPDATE (status) ON "+relation+" FROM "+loginSQL); err != nil {
			t.Errorf("revoke column-only mutation permission: %v", err)
		}
	})
	var tableWide, anyColumn bool
	if err := reader.QueryRow(ctx,
		"SELECT has_table_privilege(session_user,$1,'UPDATE'), has_any_column_privilege(session_user,$1,'UPDATE')",
		relation).Scan(&tableWide, &anyColumn); err != nil || tableWide || !anyColumn {
		t.Fatalf("not a column-only UPDATE grant: table=%t column=%t err=%v", tableWide, anyColumn, err)
	}
	if err := evidenceReaderColumnCheck(t, reader, tenant); !errors.Is(err, ErrEvidenceReaderUntrusted) {
		t.Fatalf("source-column UPDATE accepted by read-only evidence reader: %v", err)
	}
	if _, err := owner.Exec(ctx, "REVOKE UPDATE (status) ON "+relation+" FROM "+loginSQL); err != nil {
		t.Fatal(err)
	}
	if err := evidenceReaderColumnCheck(t, reader, tenant); err != nil {
		t.Fatalf("reader not restored after revoking source-column write: %v", err)
	}
}
