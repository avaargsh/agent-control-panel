package postgres

import (
	"context"
	"errors"
	"testing"
)

// The migration ledger must survive a PostgreSQL crash. A checksum alone
// cannot prove that its storage is persistent after an operator-side ALTER.
func TestMigrationLedgerRejectsUnloggedStorage(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "ALTER TABLE schema_migrations SET UNLOGGED"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("unlogged schema_migrations was accepted: %v", err)
	}
}
