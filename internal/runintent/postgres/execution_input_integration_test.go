package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

func TestExecutionInputAtomicCreateReplayAndRollback(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(901)
	raw := []byte(`{ "prompt": "hello", "number": 9007199254740993 }`)
	var err error
	intent.RequestDigest, err = runintent.ExecutionInputDigest(intent, raw)
	if err != nil {
		t.Fatal(err)
	}
	event := testEvent(intent, 1, 90101, eventCreated)
	first, created, err := repo.CreateWithInput(ctx, intent, event, raw)
	if err != nil || !created || first.ID != intent.ID {
		t.Fatalf("create=%v err=%v", created, err)
	}
	read, err := New(pool).GetExecutionInput(ctx, intent.TenantID, intent.ID)
	if err != nil || !bytes.Equal(read, raw) {
		t.Fatalf("input recovered incorrectly: %v", err)
	}
	if _, err := repo.GetExecutionInput(ctx, "foreign-tenant", intent.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}
	replay := intent
	replay.ID = testIntent(902).ID
	got, created, err := repo.CreateWithInput(ctx, replay, testEvent(replay, 1, 90102, eventCreated), raw)
	if err != nil || created || got.ID != first.ID || countOutbox(t, pool, first.ID) != 1 {
		t.Fatalf("replay=%v created=%v err=%v", got.ID, created, err)
	}
	if _, _, err := repo.Create(ctx, replay, testEvent(replay, 1, 90103, eventCreated)); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("digest-only replay bypassed immutable input: %v", err)
	}
	if _, _, err := repo.CreateWithInput(ctx, replay, testEvent(replay, 1, 90104, eventCreated), []byte("{}")); !errors.Is(err, runintent.ErrExecutionInputMismatch) {
		t.Fatalf("changed input accepted: %v", err)
	}
	rollback := testIntent(903)
	rollback.RequestDigest, err = runintent.ExecutionInputDigest(rollback, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.CreateWithInput(ctx, rollback, testEvent(rollback, 1, 90101, eventCreated), raw); err == nil {
		t.Fatal("duplicate outbox event did not fail create")
	}
	if _, err := repo.GetExecutionInput(ctx, rollback.TenantID, rollback.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rolled-back input remained: %v", err)
	}
	legacy := testIntent(904)
	legacy.RequestDigest, err = runintent.ExecutionInputDigest(legacy, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.Create(ctx, legacy, testEvent(legacy, 1, 90105, eventCreated)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetExecutionInput(ctx, legacy.TenantID, legacy.ID); !errors.Is(err, ErrExecutionInputUnavailable) {
		t.Fatalf("legacy input invented: %v", err)
	}
	if _, _, err := repo.CreateWithInput(ctx, legacy, testEvent(legacy, 1, 90106, eventCreated), raw); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("legacy row upgraded through replay: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE run_intents SET execution_input=$1 WHERE id=$2::uuid", []byte("{}"), intent.ID); err == nil {
		t.Fatal("direct input mutation accepted")
	}
	if _, err := pool.Exec(ctx, "UPDATE run_intents SET request_digest=$1 WHERE id=$2::uuid", legacy.RequestDigest, intent.ID); err == nil {
		t.Fatal("direct digest mutation accepted")
	}
	if _, err := pool.Exec(ctx, "UPDATE run_intents SET execution_input=$1 WHERE id=$2::uuid", raw, legacy.ID); err == nil {
		t.Fatal("legacy input backfill accepted")
	}
}

func TestExecutionInputMigrationRejectsDisabledGuard(t *testing.T) {
	_, pool := testRepository(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "ALTER TABLE run_intents DISABLE TRIGGER run_intent_execution_input_immutable"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("disabled input guard was accepted: %v", err)
	}
}

func TestExecutionInputMigrationUpgradeRetainsLegacyAbsence(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	legacy := testIntent(905)
	if _, _, err := repo.Create(ctx, legacy, testEvent(legacy, 1, 90501, eventCreated)); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"DROP TRIGGER run_intent_execution_input_immutable ON run_intents",
		"DROP FUNCTION reject_run_intent_execution_input_mutation()",
		"ALTER TABLE run_intents DROP COLUMN execution_input",
		"DELETE FROM schema_migrations WHERE version=10",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetExecutionInput(ctx, legacy.TenantID, legacy.ID); !errors.Is(err, ErrExecutionInputUnavailable) {
		t.Fatalf("legacy input not absent after migration: %v", err)
	}
}

func TestExecutionInputReadFailsClosedOnCorruption(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	intent := testIntent(906)
	raw := []byte(`{"prompt":"original"}`)
	var err error
	intent.RequestDigest, err = runintent.ExecutionInputDigest(intent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.CreateWithInput(ctx, intent, testEvent(intent, 1, 90601, eventCreated), raw); err != nil {
		t.Fatal(err)
	}
	// Simulate out-of-band privileged storage corruption in disposable DB.
	if _, err := pool.Exec(ctx, "ALTER TABLE run_intents DISABLE TRIGGER run_intent_execution_input_immutable"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE run_intents SET execution_input=$1 WHERE id=$2::uuid", []byte(`{"prompt":"tampered"}`), intent.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.GetExecutionInput(ctx, intent.TenantID, intent.ID); !errors.Is(err, ErrCorruptRecord) || got != nil {
		t.Fatalf("corrupt input returned to dispatcher: %v", err)
	}
}
