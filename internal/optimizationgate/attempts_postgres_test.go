package optimizationgate

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	runpostgres "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func disposableAttemptStore(t *testing.T) (*AttemptStore, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN absent: real PostgreSQL integration evidence unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("opt_gate_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		_ = admin.Close(context.Background())
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop isolated attempt schema: %v", err)
		}
		_ = admin.Close(context.Background())
	})
	if err := runpostgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("apply authoritative v13 migration: %v", err)
	}
	if err := runpostgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("recheck v13 migration and RLS guards: %v", err)
	}
	return NewAttemptStore(pool), pool
}

func attemptFixture(t *testing.T, store *AttemptStore) (BaselinePolicy, []byte, map[string]ed25519.PublicKey, testEvidenceReader) {
	t.Helper()
	base, receipt, key, keys := fixture()
	base.VerificationNonce = ""
	issued, err := store.IssueReviewAttempt(context.Background(), base, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	receipt.VerificationNonce = issued.VerificationNonce
	baseline := []byte(`{"scenario":"frozen-eval","verdict":"ok"}`)
	candidate := []byte(`{"scenario":"frozen-eval","verdict":"ok","optimized":true}`)
	receipt.BaselineEvidenceDigest = evidenceSHA(baseline)
	receipt.CandidateEvidenceDigest = evidenceSHA(candidate)
	return issued, signed(receipt, key), keys, testEvidenceReader{
		receipt.BaselineEvidenceDigest:  baseline,
		receipt.CandidateEvidenceDigest: candidate,
	}
}

func TestPostgresAttemptConsumesExactlyOnceUnderConcurrency(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	policy, wire, keys, reader := attemptFixture(t, store)
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, reader)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	accepted, replayed := 0, 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrAttemptUnavailable):
			replayed++
		default:
			t.Fatalf("unexpected concurrent consumption error: %v", err)
		}
	}
	if accepted != 1 || replayed != 11 {
		t.Fatalf("nonce was consumed more than once or no winner: accepted=%d rejected=%d", accepted, replayed)
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM optimization_verification_attempts
		WHERE verification_nonce=$1 AND consumed_at IS NOT NULL AND signed_receipt_digest=$2`,
		policy.VerificationNonce, digestBytes(wire)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("durable consumption not recorded exactly once: count=%d err=%v", count, err)
	}
}

func TestPostgresAttemptRejectsUnknownOrForgedScope(t *testing.T) {
	store, _ := disposableAttemptStore(t)
	policy, wire, keys, reader := attemptFixture(t, store)
	unknown := policy
	unknown.VerificationNonce = strings.Repeat("e", 64)
	var envelope SignedReceipt
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	var receipt EvaluationReceipt
	if err := json.Unmarshal(envelope.Payload, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.VerificationNonce = unknown.VerificationNonce
	_, _, key, _ := fixture()
	if _, err := store.ConsumeReviewEvidence(context.Background(), unknown, signed(receipt, key), keys, reader); !errors.Is(err, ErrAttemptUnavailable) {
		t.Fatalf("unissued but otherwise valid signed attempt should be rejected by PostgreSQL: %v", err)
	}
	policy.ProjectID = "project-foreign"
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, reader); err == nil {
		t.Fatal("cross-project signed receipt accepted")
	}
}

func TestPostgresAttemptRefusesInvalidEvidenceWithoutConsuming(t *testing.T) {
	store, _ := disposableAttemptStore(t)
	policy, wire, keys, reader := attemptFixture(t, store)
	bad := testEvidenceReader{}
	for digest, value := range reader {
		bad[digest] = append([]byte(nil), value...)
	}
	for digest := range bad {
		bad[digest][0] ^= 1
		break
	}
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, bad); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("tampered raw data got accepted: %v", err)
	}
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, reader); err != nil {
		t.Fatalf("legitimate evidence cannot consume after failed input: %v", err)
	}
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, reader); !errors.Is(err, ErrAttemptUnavailable) {
		t.Fatalf("successful consumption replayed: %v", err)
	}
}

func TestPostgresAttemptRejectsMutationDeleteAndSchemaDrift(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	policy, wire, keys, reader := attemptFixture(t, store)
	if _, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, reader); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"UPDATE optimization_verification_attempts SET consumed_at=NULL",
		"UPDATE optimization_verification_attempts SET tenant_id='other'",
		"DELETE FROM optimization_verification_attempts",
		"TRUNCATE optimization_verification_attempts",
	} {
		if _, err := pool.Exec(context.Background(), stmt); err == nil {
			t.Fatalf("irreversible attempt ledger mutated by: %s", stmt)
		}
	}
	if _, err := pool.Exec(context.Background(), "ALTER TABLE optimization_verification_attempts DISABLE ROW LEVEL SECURITY"); err != nil {
		t.Fatal(err)
	}
	if err := runpostgres.Migrate(context.Background(), pool); !errors.Is(err, runpostgres.ErrSchemaDrift) {
		t.Fatalf("RLS disabled but migration validation did not fail closed: %v", err)
	}
}

func TestPostgresAttemptExpiresOnDatabaseClock(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	policy, receipt, key, keys := fixture()
	policy.VerificationNonce = ""
	issued, err := store.IssueReviewAttempt(context.Background(), policy, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	receipt.VerificationNonce = issued.VerificationNonce
	assets := testEvidenceReader{}
	baseline := []byte("baseline")
	candidate := []byte("candidate")
	receipt.BaselineEvidenceDigest = evidenceSHA(baseline)
	receipt.CandidateEvidenceDigest = evidenceSHA(candidate)
	assets[receipt.BaselineEvidenceDigest] = baseline
	assets[receipt.CandidateEvidenceDigest] = candidate
	if _, err := pool.Exec(context.Background(), "SELECT pg_sleep(1.1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeReviewEvidence(context.Background(), issued, signed(receipt, key), keys, assets); !errors.Is(err, ErrAttemptUnavailable) {
		t.Fatalf("expired attempt was consumed: %v", err)
	}
}


// Issue errors must preserve the PostgreSQL cause as well as the package-level
// fail-closed classification so operators can distinguish schema drift.
func TestPostgresIssuePreservesJournalWriteError(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	if _, err := pool.Exec(context.Background(),
		"ALTER TABLE optimization_verification_attempts RENAME TO optimization_verification_attempts_missing"); err != nil {
		t.Fatalf("inject missing attempt journal: %v", err)
	}
	policy, _, _, _ := fixture()
	policy.VerificationNonce = ""
	_, err := store.IssueReviewAttempt(context.Background(), policy, time.Minute)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
		t.Fatalf("issue did not preserve PostgreSQL undefined-table error: pgErr=%v err=%v", pgErr, err)
	}
	if !errors.Is(err, ErrAttemptUnconfigured) {
		t.Fatalf("issue lost fail-closed classification: %v", err)
	}
}

// A trigger failure after the preflight and evidence read exercises the final
// atomic consume UPDATE, not the earlier read-only nonce check.
func TestPostgresConsumePreservesJournalWriteError(t *testing.T) {
	store, pool := disposableAttemptStore(t)
	policy, wire, keys, reader := attemptFixture(t, store)
	if _, err := pool.Exec(context.Background(), `CREATE FUNCTION reject_test_attempt_consume()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'injected attempt journal write failure' USING ERRCODE='P0001';
		END;
		$$`); err != nil {
		t.Fatalf("create failure injection function: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `CREATE TRIGGER reject_test_attempt_consume
		BEFORE UPDATE ON optimization_verification_attempts
		FOR EACH ROW EXECUTE FUNCTION reject_test_attempt_consume()`); err != nil {
		t.Fatalf("create failure injection trigger: %v", err)
	}
	_, err := store.ConsumeReviewEvidence(context.Background(), policy, wire, keys, reader)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("consume did not preserve PostgreSQL trigger error: pgErr=%v err=%v", pgErr, err)
	}
	if !errors.Is(err, ErrAttemptUnconfigured) {
		t.Fatalf("consume lost fail-closed classification: %v", err)
	}
}
