package inboxtransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

const settlementKillMarker = "INBOX_COMMITTED_BEFORE_ACK"

type killProcessBeforeACK struct{}

func (killProcessBeforeACK) Ack(context.Context) error {
	_, _ = fmt.Fprintln(os.Stdout, settlementKillMarker)
	_ = os.Stdout.Sync()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	if err := proc.Kill(); err != nil {
		return err
	}
	return errors.New("process should have been killed")
}

func (killProcessBeforeACK) DeadLetter(context.Context, string) error {
	return errors.New("unexpected dead-letter disposition during normal delivery")
}

func settlementKillEvent() postgres.Event {
	return postgres.Event{
		ID:               "00000000-0000-4000-8000-000000000121",
		Producer:         "test-producer",
		Type:             "agent.test.changed",
		SchemaVersion:    1,
		TenantID:         "tenant-a",
		AggregateType:    "agent",
		AggregateID:      "agent-kill",
		AggregateVersion: 1,
		OccurredAt:       time.Now().UTC(),
		CorrelationID:    "settlement-kill",
		Payload:          json.RawMessage(`{"version":1}`),
	}
}

// Called in an actual second OS process, not a goroutine. Its first broker
// ACK callback terminates this process after the PostgreSQL receive commits.
func TestSettlementSIGKILLHelper(t *testing.T) {
	if os.Getenv("ACP_SIGKILL_HELPER") != "1" {
		return
	}
	dsn := os.Getenv("PGTEST_DSN")
	schema := os.Getenv("ACP_SIGKILL_SCHEMA")
	if dsn == "" || !strings.HasPrefix(schema, "test_inbox_settlement_") {
		t.Fatal("missing isolated PostgreSQL process test configuration")
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := HandleDelivery(ctx, postgres.New(pool), killProcessBeforeACK{}, "billing-consumer", settlementKillEvent()); err != nil {
		t.Fatalf("expected process termination at ACK boundary: %v", err)
	}
	t.Fatal("unexpected normal return instead of process termination")
}

func TestSettlementSIGKILLAfterPostgresCommitBeforeACKIsRedeliverable(t *testing.T) {
	repository, pool := settlementPostgres(t)
	schema := pool.Config().ConnConfig.RuntimeParams["search_path"]
	cmd := exec.Command(os.Args[0], "-test.run=^TestSettlementSIGKILLHelper$")
	cmd.Env = append(os.Environ(), "ACP_SIGKILL_HELPER=1", "ACP_SIGKILL_SCHEMA="+schema)
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != -1 || !strings.Contains(string(output), settlementKillMarker) {
		t.Fatalf("child was not terminated after durable receive (err=%v, output=%s)", err, output)
	}

	ctx := context.Background()
	event := settlementKillEvent()
	var count int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM inbox_events WHERE consumer_name='billing-consumer' AND event_id=$1::uuid",
		event.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("committed Inbox row lost during receiver SIGKILL: %d", count)
	}

	// Restart is represented by the parent process and a new PostgreSQL
	// connection/settlement callback. This is not a live broker redelivery.
	delivery := &databaseObservingDelivery{pool: pool, eventID: event.ID}
	if err := HandleDelivery(ctx, repository, delivery, "billing-consumer", event); err != nil {
		t.Fatalf("restart redelivery of committed event: %v", err)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, "billing-consumer", acceptAllApplier{})
	if err != nil || !applied.Applied {
		t.Fatalf("apply persisted event once: %+v, %v", applied, err)
	}
	if err := HandleDelivery(ctx, repository, delivery, "billing-consumer", event); err != nil {
		t.Fatalf("redelivery after projection: %v", err)
	}
	second, err := repository.ApplyNextInboxEvent(ctx, "billing-consumer", acceptAllApplier{})
	if err != nil || second.Found {
		t.Fatalf("duplicate was applied a second time: %+v, %v", second, err)
	}
	var rows, version int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM inbox_events WHERE consumer_name='billing-consumer'",
	).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		"SELECT last_applied_version FROM inbox_cursors WHERE consumer_name='billing-consumer' AND tenant_id=$1 AND aggregate_id=$2",
		event.TenantID, event.AggregateID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || version != 1 || delivery.ackCalls != 2 {
		t.Fatalf("non-idempotent crash recovery: rows=%d cursor=%d ACK calls=%d", rows, version, delivery.ackCalls)
	}
}
