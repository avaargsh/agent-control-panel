
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type testInboxApplier struct {
	fail bool
}

func (a *testInboxApplier) Supports(event InboxEvent) bool {
	return event.SchemaVersion == 1 && event.Type == "agent.test.changed"
}

func (a *testInboxApplier) Apply(ctx context.Context, tx pgx.Tx, event InboxEvent) error {
	if a.fail {
		return errors.New("projection temporarily unavailable")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO inbox_test_projection (
			consumer_name,tenant_id,aggregate_id,aggregate_version,event_id
		) VALUES ('test-consumer',$1,$2,$3,$4::uuid)
	`, event.TenantID, event.AggregateID, int64(event.AggregateVersion), event.ID)
	return err
}

func testInboxEvent(tenantID, aggregateID string, version uint64, eventID int) Event {
	return Event{
		ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", eventID),
		Producer: "test-producer",
		Type: "agent.test.changed",
		SchemaVersion: 1,
		TenantID: tenantID,
		AggregateType: "agent",
		AggregateID: aggregateID,
		AggregateVersion: version,
		OccurredAt: time.Now().UTC(),
		CorrelationID: "test-correlation",
		Payload: json.RawMessage(fmt.Sprintf("{\"version\":%d}", version)),
	}
}

func setupInboxProjection(t *testing.T, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE inbox_test_projection (
			consumer_name text NOT NULL,
			tenant_id text NOT NULL,
			aggregate_id text NOT NULL,
			aggregate_version bigint NOT NULL,
			event_id uuid NOT NULL,
			PRIMARY KEY (consumer_name,tenant_id,aggregate_id,aggregate_version)
		)
	`)
	if err != nil {
		t.Fatalf("create Inbox projection fixture: %v", err)
	}
}
