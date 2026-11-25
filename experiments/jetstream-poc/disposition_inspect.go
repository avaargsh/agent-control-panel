package jetstreampoc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"
)

// DispositionInspection is a point-in-time diagnostic, not permission to ACK,
// publish, modify the journal, or resolve UNKNOWN. Broker state may change
// immediately after inspection. No raw evidence bytes are returned.
type DispositionInspection struct {
	JournalState string
	BrokerState  string
}

// InspectDisposition reads a single explicitly scoped disposition and checks
// its retained broker evidence. The caller must supply the trusted POC
// configuration and already-authorized database and broker connections.
// It neither creates a disposition nor reconciles a publication.
func (j *DispositionJournal) InspectDisposition(ctx context.Context, js jetstream.JetStream, cfg Config, sequence int64) (DispositionInspection, error) {
	out := DispositionInspection{JournalState: "NOT_CHECKED", BrokerState: "NOT_CHECKED"}
	if _, err := ValidateDispositionJournal(j); err != nil {
		return out, err
	}
	if js == nil || cfg.SourceStream == "" || cfg.SourceConsumer == "" || cfg.DLQStream == "" || cfg.DLQSubject == "" || sequence <= 0 {
		return out, ErrDispositionConflict
	}
	var stream, subject string
	var evidence []byte
	var started, published bool
	err := j.pool.QueryRow(ctx, `
		SELECT dlq_stream,dlq_subject,evidence,publish_started,published
		FROM poc_dlq_dispositions
		WHERE source_stream=$1 AND source_consumer=$2 AND source_sequence=$3
	`, cfg.SourceStream, cfg.SourceConsumer, sequence).Scan(&stream, &subject, &evidence, &started, &published)
	if errors.Is(err, pgx.ErrNoRows) {
		out.JournalState = "NOT_FOUND"
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("inspect disposition journal: %w", err)
	}
	if published && !started {
		return out, ErrDispositionConflict
	}
	if stream != cfg.DLQStream || !strings.HasPrefix(subject, cfg.DLQSubject+".") {
		return out, ErrDispositionConflict
	}
	suffix := strings.TrimPrefix(subject, cfg.DLQSubject+".")
	if suffix == "" || strings.ContainsAny(suffix, ".*> \t\r\n") {
		return out, ErrDispositionConflict
	}
	switch {
	case published:
		out.JournalState = "CONFIRMED"
	case started:
		out.JournalState = "ATTEMPT_UNCONFIRMED"
	default:
		out.JournalState = "NOT_STARTED"
	}

	dlq, err := js.Stream(ctx, stream)
	if err != nil {
		return out, fmt.Errorf("inspect DLQ stream: %w", err)
	}
	raw, err := dlq.GetLastMsgForSubject(ctx, subject)
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		out.BrokerState = "MISSING"
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("inspect retained DLQ evidence: %w", err)
	}
	if raw == nil {
		return out, ErrDispositionConflict
	}
	if raw.Subject == subject && bytes.Equal(raw.Data, evidence) {
		out.BrokerState = "MATCHING"
	} else {
		out.BrokerState = "MISMATCH"
	}
	return out, nil
}
