package journal

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func assertCommandCommitDenied(t *testing.T, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("expected deferred Command commit constraint SQLSTATE 23514, got %v", err)
	}
}

// setup() deliberately initializes only the minimal Journal tables. An
// 0012 installation must respect the full source-owned migration stack,
// including 0010's upstream revocation verification and 0011 Command roles.
func installCommandCommitMigrations(t *testing.T, repo *Repository) []byte {
	t.Helper()
	var commitSQL []byte
	for _, name := range []string{
		"0002_lease_intents.sql",
		"0003_lease_outbox_immutable.sql",
		"0004_lease_runtime_roles.sql",
		"0006_lease_commit_integrity.sql",
		"0007_tenant_login_rls.sql",
		"0008_tenant_login_oid_fence.sql",
		"0009_tenant_login_revoke_evict.sql",
		"0010_tenant_revoke_postcommit_verify.sql",
		"0011_command_tenant_login_rls.sql",
		"0012_command_commit_integrity.sql",
	} {
		sql, err := os.ReadFile("../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.pool.Exec(context.Background(), string(sql)); err != nil {
			t.Fatalf("apply source-owned %s: %v", name, err)
		}
		if name == "0012_command_commit_integrity.sql" {
			commitSQL = sql
		}
	}
	return commitSQL
}

// An independently authorized Command writer has SQL INSERT rights, but that
// must not allow it to commit an orphan or forged Outbox by bypassing the Go
// RecordPermitUnavailable transaction. This negative intentionally fails
// before the independent DB's commit barrier exists.
func TestCommandCommitRejectsOrphanAndForgedOutbox(t *testing.T) {
	repo := setup(t)
	ctx := context.Background()
	// Run the real owner-only migrations, not a mocked Go validation.
	installCommandCommitMigrations(t, repo)
	orphan := sample()
	orphan.CommandID = "direct-sql-orphan"
	_, err := repo.pool.Exec(ctx, `INSERT INTO public.sandbox_journal_commands
	  (tenant_id,sandbox_uid,command_id,run_id,runtime_attempt_id,request_digest)
	  VALUES($1,$2,$3,$4,$5,$6)`,
		orphan.TenantID, orphan.SandboxUID, orphan.CommandID,
		orphan.RunID, orphan.RuntimeAttemptID, orphan.RequestDigest)
	assertCommandCommitDenied(t, err)
	if _, err := repo.Get(ctx, orphan.TenantID, orphan.SandboxUID, orphan.CommandID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected orphan command was committed: %v", err)
	}

	forged := sample()
	forged.CommandID = "direct-sql-forged-outbox"
	tx, err := repo.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `INSERT INTO public.sandbox_journal_commands
	  (tenant_id,sandbox_uid,command_id,run_id,runtime_attempt_id,request_digest)
	  VALUES($1,$2,$3,$4,$5,$6)`,
		forged.TenantID, forged.SandboxUID, forged.CommandID,
		forged.RunID, forged.RuntimeAttemptID, forged.RequestDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.sandbox_journal_outbox
	  (tenant_id,sandbox_uid,command_id,generation,event_type,payload)
	  VALUES($1,$2,$3,1,'sandbox.command.permit-unavailable',
	    jsonb_build_object('run_id','forged-run','runtime_attempt_id',$4::text,
	      'request_digest',$5::text,'private_token','should-not-persist'))`,
		forged.TenantID, forged.SandboxUID, forged.CommandID,
		forged.RuntimeAttemptID, forged.RequestDigest); err != nil {
		t.Fatal(err)
	}
	assertCommandCommitDenied(t, tx.Commit(ctx))
	if _, err := repo.Get(ctx, forged.TenantID, forged.SandboxUID, forged.CommandID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("forged Outbox was committed: %v", err)
	}

	valid := sample()
	if got, created, err := repo.RecordPermitUnavailable(ctx, valid); err != nil || !created || got.Identity != valid {
		t.Fatalf("valid atomic Command/Outbox failed: created=%t got=%+v err=%v", created, got, err)
	}
	if got, created, err := repo.RecordPermitUnavailable(ctx, valid); err != nil || created || got.Identity != valid {
		t.Fatalf("idempotent replay failed: created=%t got=%+v err=%v", created, got, err)
	}
}

// A migration cannot retroactively bless committed source facts that lack
// their original Outbox. Only the disposable database owner injects history
// with triggers disabled; production runtime principals have no DDL rights.
func TestCommandCommitMigrationRefusesHistoricalOrphan(t *testing.T) {
	repo := setup(t)
	ctx := context.Background()
	legacy := sample()
	legacy.CommandID = "historical-orphan"
	raw := installCommandCommitMigrations(t, repo)
	var err error

	inject := func(disable bool) {
		t.Helper()
		tx, err := repo.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(ctx, "ALTER TABLE public.sandbox_journal_commands DISABLE TRIGGER USER"); err != nil {
			t.Fatal(err)
		}
		if disable {
			_, err = tx.Exec(ctx, `INSERT INTO public.sandbox_journal_commands
				(tenant_id,sandbox_uid,command_id,run_id,runtime_attempt_id,request_digest)
				VALUES($1,$2,$3,$4,$5,$6)`,
				legacy.TenantID, legacy.SandboxUID, legacy.CommandID,
				legacy.RunID, legacy.RuntimeAttemptID, legacy.RequestDigest)
		} else {
			_, err = tx.Exec(ctx, `DELETE FROM public.sandbox_journal_commands
				WHERE tenant_id=$1 AND sandbox_uid=$2 AND command_id=$3`,
				legacy.TenantID, legacy.SandboxUID, legacy.CommandID)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "ALTER TABLE public.sandbox_journal_commands ENABLE TRIGGER USER"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	inject(true)
	defer inject(false)
	_, err = repo.pool.Exec(ctx, string(raw))
	assertCommandCommitDenied(t, err)
	if _, err := repo.Get(ctx, legacy.TenantID, legacy.SandboxUID, legacy.CommandID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("incomplete historical command was treated as a valid receipt: %v", err)
	}
	inject(false)
	// The candidate migration is idempotent on clean, original committed
	// history, including a normal atomic repository transaction.
	healthy := sample()
	if _, created, err := repo.RecordPermitUnavailable(ctx, healthy); err != nil || !created {
		t.Fatalf("write valid immutable command before migration replay: created=%t err=%v", created, err)
	}
	if _, err := repo.pool.Exec(ctx, string(raw)); err != nil {
		t.Fatalf("migration replay rejected valid original history: %v", err)
	}
	if _, err := repo.Get(ctx, healthy.TenantID, healthy.SandboxUID, healthy.CommandID); err != nil {
		t.Fatalf("valid command lost after migration replay: %v", err)
	}
}
