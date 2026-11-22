package journal

import (
	"context"
	"errors"
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

// An independently authorized Command writer has SQL INSERT rights, but that
// must not allow it to commit an orphan or forged Outbox by bypassing the Go
// RecordPermitUnavailable transaction. This negative intentionally fails
// before the independent DB's commit barrier exists.
func TestCommandCommitRejectsOrphanAndForgedOutbox(t *testing.T) {
	repo := setup(t)
	ctx := context.Background()
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
