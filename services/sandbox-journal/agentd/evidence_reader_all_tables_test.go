package agentd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Exercise the already merged LOGIN/OID policy against actual source rows
// in all three tables, not just the Attempt table or an absent foreign row.
func TestEvidenceReaderTwoLoginsAllSourceTables(t *testing.T) {
	owner := testDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmdA, a := startOwnedTestProcess(t, "0.2")
	cmdB, b := startOwnedTestProcess(t, "0.2")
	b.TenantID = "agentd-tenant-b"
	b.RunID = "22222222-2222-4222-8222-222222222222"
	b.RuntimeAttemptID = "runtime-attempt-b"
	b.SandboxUID = "sandbox-uid-b"
	b.CommandID = "command-b"
	b.AttemptID = "attempt-b"
	b.ProviderCommandUID = "provider-command-b"
	seedAlreadyAuthorizedAttempt(t, owner, a)
	seedAlreadyAuthorizedAttempt(t, owner, b)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdA.Wait(); err == nil || cmdA.ProcessState.ExitCode() != 7 {
		t.Fatalf("tenant A requires a real nonzero Wait: %v", err)
	}
	if err := cmdB.Wait(); err == nil || cmdB.ProcessState.ExitCode() != 7 {
		t.Fatalf("tenant B requires a real nonzero Wait: %v", err)
	}
	for _, ref := range []Ref{a, b} {
		state := cmdA.ProcessState
		if ref == b {
			state = cmdB.ProcessState
		}
		if _, err := RecordWaitOutcome(ctx, owner, ref, state, priv); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectAndJournal(ctx, owner, ref, pub, priv); err != nil {
			t.Fatal(err)
		}
	}
	tables := []string{"sandbox_agentd_attempts", "sandbox_agentd_terminal_receipts", "sandbox_agentd_inspect_events"}
	count := func(q interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}, table, tenant string) int {
		t.Helper()
		var n int
		if err := q.QueryRow(ctx, "SELECT count(*) FROM public."+table+" WHERE tenant_id=$1", tenant).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}
	for _, table := range tables {
		for _, tenant := range []string{a.TenantID, b.TenantID} {
			if n := count(owner, table, tenant); n != 1 {
				t.Fatalf("missing owner positive control: %s %s rows=%d", table, tenant, n)
			}
		}
	}

	readerA := newEvidenceReaderPool(t, owner, a.TenantID)
	readerB := newEvidenceReaderPool(t, owner, b.TenantID)
	for _, tc := range []struct {
		pool         *pgxpool.Pool
		own, foreign string
	}{
		{readerA, a.TenantID, b.TenantID},
		{readerB, b.TenantID, a.TenantID},
	} {
		t.Run(tc.own, func(t *testing.T) {
			check := func(q interface {
				QueryRow(context.Context, string, ...any) pgx.Row
			}, wantOwn int) {
				t.Helper()
				for _, table := range tables {
					if own, foreign := count(q, table, tc.own), count(q, table, tc.foreign); own != wantOwn || foreign != 0 {
						t.Fatalf("%s: own=%d want=%d foreign=%d", table, own, wantOwn, foreign)
					}
				}
			}
			for _, forged := range []string{tc.foreign, ""} {
				tx, err := tc.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if err := verifyEvidenceReaderLogin(ctx, tx, tc.own); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", forged); err != nil {
					t.Fatal(err)
				}
				check(tx, 1)
				nested, err := tx.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer nested.Rollback(ctx)
				if _, err := nested.Exec(ctx, "SET LOCAL ROLE sandbox_agentd_evidence_reader"); err != nil {
					t.Fatal(err)
				}
				check(nested, 1)
				if err := nested.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				check(tx, 1)
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
			tc.pool.Reset()
			check(tc.pool, 1)
			// Hold the same authenticated connection over a committed owner
			// revocation, but start fresh statement snapshots after revocation.
			conn, err := tc.pool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Release()
			var login string
			if err := conn.QueryRow(ctx, "SELECT session_user").Scan(&login); err != nil {
				t.Fatal(err)
			}
			tag, err := owner.Exec(ctx, "DELETE FROM public.sandbox_agentd_evidence_reader_tenants WHERE login_role=$1", login)
			if err != nil || tag.RowsAffected() != 1 {
				t.Fatalf("revoke binding: rows=%d err=%v", tag.RowsAffected(), err)
			}
			check(conn, 0)
			tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if err := verifyEvidenceReaderLogin(ctx, tx, tc.own); err == nil {
				t.Fatal("revoked binding was accepted")
			}
		})
	}
}
