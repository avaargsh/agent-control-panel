package jetstreampoc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Exercise the diagnostic API on an actual ambiguous publication, with a
// SELECT-only test role. SET ROLE is a fixture, not a deployed identity.
func TestRealDispositionInspectorWithRestrictedRoleAndAmbiguousPublish(t *testing.T) {
	repository, pool := pocRepository(t)
	js, consumer, dlq, cfg := pocNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	role := fmt.Sprintf("poc_inspect_%d", time.Now().UnixNano())
	schema := pool.Config().ConnConfig.RuntimeParams["search_path"]
	if _, err := pool.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := pool.Exec(cleanup, "DROP OWNED BY "+role); err != nil {
			t.Error(err)
			return
		}
		if _, err := pool.Exec(cleanup, "DROP ROLE "+role); err != nil {
			t.Error(err)
		}
	})
	for _, statement := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT SELECT ON poc_dlq_dispositions TO " + role,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	inspectConfig := pool.Config()
	inspectConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE "+role)
		return err
	}
	inspectPool, err := pgxpool.NewWithConfig(ctx, inspectConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inspectPool.Close)
	var currentRole string
	if err := inspectPool.QueryRow(ctx, "SELECT current_user").Scan(&currentRole); err != nil || currentRole != role {
		t.Fatalf("diagnostic connection did not assume restricted role: %q err=%v", currentRole, err)
	}

	worker := NewDispositionJournal(pool)
	inspector := NewDispositionJournal(inspectPool)
	event := pocEvent(8991, 1)
	publishEvent(t, ctx, js, cfg.SourceSubject, event)
	if err := HandleMessage(ctx, repository, js, nextMessage(t, consumer), cfg, worker); err != nil {
		t.Fatal(err)
	}
	applied, err := repository.ApplyNextInboxEvent(ctx, cfg.ConsumerName, allowPOCProjection{})
	if err != nil || !applied.Applied {
		t.Fatalf("original not applied: %+v err=%v", applied, err)
	}
	// Fail only the confirmation UPDATE after the real PubAck.
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION reject_inspection_fixture_confirm() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'inspection fixture confirmation failure';
		END; $$;
		CREATE TRIGGER reject_inspection_fixture_confirm
		BEFORE UPDATE ON poc_dlq_dispositions
		FOR EACH ROW WHEN (NEW.published AND NOT OLD.published)
		EXECUTE FUNCTION reject_inspection_fixture_confirm();
	`); err != nil {
		t.Fatal(err)
	}
	conflict := event
	conflict.Payload = []byte(`{"version":8992}`)
	publishEvent(t, ctx, js, cfg.SourceSubject, conflict)
	delivery := nextMessage(t, consumer)
	meta, err := delivery.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	err = HandleMessage(ctx, repository, js, delivery, cfg, worker)
	if err == nil || !strings.Contains(err.Error(), "inspection fixture confirmation failure") {
		t.Fatalf("expected exact injected confirmation failure: %v", err)
	}
	if _, err := pool.Exec(ctx, "DROP TRIGGER reject_inspection_fixture_confirm ON poc_dlq_dispositions"); err != nil {
		t.Fatal(err)
	}

	sequence := int64(meta.Sequence.Stream)
	check := func(wantBroker string) {
		t.Helper()
		got, err := inspector.InspectDisposition(ctx, js, cfg, sequence)
		if err != nil || got.JournalState != "ATTEMPT_UNCONFIRMED" || got.BrokerState != wantBroker {
			t.Fatalf("unexpected diagnostic: %+v err=%v", got, err)
		}
	}
	check("MATCHING")
	for _, sql := range []string{
		"UPDATE poc_dlq_dispositions SET published=true,published_at=clock_timestamp()",
		"DELETE FROM poc_dlq_dispositions",
		"TRUNCATE poc_dlq_dispositions",
	} {
		_, err := inspectPool.Exec(ctx, sql)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("diagnostic role could modify journal or failed with wrong error: %v", err)
		}
	}
	raw, err := dlq.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := dlq.DeleteMsg(ctx, raw.Sequence); err != nil {
		t.Fatal(err)
	}
	check("MISSING")
	replay := nextMessage(t, consumer)
	replayMeta, err := replay.Metadata()
	if err != nil || replayMeta.Sequence.Stream != meta.Sequence.Stream || replayMeta.NumDelivered < 2 {
		t.Fatalf("inspection ACKed or changed source delivery: %+v err=%v", replayMeta, err)
	}
	if err := HandleMessage(ctx, repository, js, replay, cfg, worker); !errors.Is(err, ErrDLQPublishUncertain) {
		t.Fatalf("diagnosis must not grant re-publication or ACK authority: %v", err)
	}
	check("MISSING")
	var started, published bool
	if err := pool.QueryRow(ctx, "SELECT publish_started,published FROM poc_dlq_dispositions").Scan(&started, &published); err != nil || !started || published {
		t.Fatalf("inspection changed durable attempt: started=%t published=%t err=%v", started, published, err)
	}
	info, err := dlq.Info(ctx)
	if err != nil || info.State.Msgs != 0 {
		t.Fatalf("inspection or replay recreated missing evidence: %+v err=%v", info, err)
	}
}
