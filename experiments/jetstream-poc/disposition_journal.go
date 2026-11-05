package jetstreampoc

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrDispositionJournalRequired = errors.New("durable DLQ disposition journal is required")
	ErrDispositionConflict        = errors.New("conflicting DLQ disposition identity or evidence")
	ErrDLQEvidenceMissing         = errors.New("confirmed DLQ evidence is missing from broker")
	ErrDLQEvidenceConflict        = errors.New("broker DLQ evidence differs from immutable disposition")
	ErrDLQPublishUncertain       = errors.New("prior DLQ publication attempt is ambiguous and needs reconciliation")
)

// DispositionJournal is an isolated POC table, deliberately NOT an ACP
// production migration. The source stream+consumer+sequence is the durable
// unique identity, independent of a broker's finite Msg-ID deduplication.
type DispositionJournal struct {
	pool *pgxpool.Pool
}

func NewDispositionJournal(pool *pgxpool.Pool) *DispositionJournal {
	return &DispositionJournal{pool: pool}
}

func ValidateDispositionJournal(j *DispositionJournal) (*DispositionJournal, error) {
	if j == nil || j.pool == nil {
		return nil, ErrDispositionJournalRequired
	}
	return j, nil
}

// Migrate is POC-only; no record may be removed while its source delivery,
// DLQ retention, and operator reconciliation have not been independently
// completed. Production IAM, tamper protection and retention are unproven.
func (j *DispositionJournal) Migrate(ctx context.Context) error {
	if _, err := ValidateDispositionJournal(j); err != nil {
		return err
	}
	_, err := j.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS poc_dlq_dispositions (
			source_stream text NOT NULL CHECK (source_stream <> ''),
			source_consumer text NOT NULL CHECK (source_consumer <> ''),
			source_sequence bigint NOT NULL CHECK (source_sequence > 0),
			delivery_hash text NOT NULL CHECK (delivery_hash ~ '^[a-f0-9]{64}$'),
			reason text NOT NULL CHECK (reason <> ''),
			dlq_stream text NOT NULL CHECK (dlq_stream <> ''),
			dlq_subject text NOT NULL CHECK (dlq_subject <> ''),
			evidence bytea NOT NULL,
			publish_started boolean NOT NULL DEFAULT false,
			published boolean NOT NULL DEFAULT false,
			created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
			published_at timestamptz,
			PRIMARY KEY (source_stream, source_consumer, source_sequence),
			CONSTRAINT poc_dlq_published_at_check CHECK (
				(published AND published_at IS NOT NULL) OR
				(NOT published AND published_at IS NULL)
			)
		)`)
	if err != nil {
		return fmt.Errorf("create isolated POC disposition journal: %w", err)
	}
	return nil
}

type dispositionRecord struct {
	stream   string
	consumer string
	sequence int64
	hash     string
	reason   string
	dlq      string
	subject  string
	evidence []byte
}

// ensure persists an immutable intent *before* broker publication. It fails
// closed if a same-sequence redelivery changes disposition contents. The
// published bit is only a hint; the broker record is always checked again
// before source ACK, and missing evidence is never recreated blindly.
func (j *DispositionJournal) ensure(ctx context.Context, record dispositionRecord) (bool, bool, error) {
	if _, err := ValidateDispositionJournal(j); err != nil {
		return false, false, err
	}
	_, err := j.pool.Exec(ctx, `
		INSERT INTO poc_dlq_dispositions (
			source_stream,source_consumer,source_sequence,delivery_hash,
			reason,dlq_stream,dlq_subject,evidence
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (source_stream,source_consumer,source_sequence) DO NOTHING
	`, record.stream, record.consumer, record.sequence, record.hash,
		record.reason, record.dlq, record.subject, record.evidence)
	if err != nil {
		return false, false, fmt.Errorf("persist immutable DLQ disposition intent: %w", err)
	}
	var hash, reason, dlq, subject string
	var data []byte
	var published, publishStarted bool
	err = j.pool.QueryRow(ctx, `
		SELECT delivery_hash,reason,dlq_stream,dlq_subject,evidence,publish_started,published
		FROM poc_dlq_dispositions
		WHERE source_stream=$1 AND source_consumer=$2 AND source_sequence=$3
	`, record.stream, record.consumer, record.sequence).Scan(
		&hash, &reason, &dlq, &subject, &data, &publishStarted, &published)
	if err != nil {
		return false, false, fmt.Errorf("read immutable DLQ disposition intent: %w", err)
	}
	if hash != record.hash || reason != record.reason || dlq != record.dlq ||
		subject != record.subject || !bytes.Equal(data, record.evidence) {
		return false, false, ErrDispositionConflict
	}
	return published, publishStarted, nil
}

// markPublishAttempt is durable BEFORE issuing JetStream Publish.
// If this step succeeds and PubAck/PG confirm is later lost, a missing
// retained broker record means UNKNOWN and must NOT be auto-republished.
func (j *DispositionJournal) markPublishAttempt(ctx context.Context, record dispositionRecord) error {
	if _, err := ValidateDispositionJournal(j); err != nil {
		return err
	}
	tag, err := j.pool.Exec(ctx, `
		UPDATE poc_dlq_dispositions SET publish_started=TRUE
		WHERE source_stream=$1 AND source_consumer=$2 AND source_sequence=$3
		  AND delivery_hash=$4 AND reason=$5 AND dlq_stream=$6
		  AND dlq_subject=$7 AND evidence=$8 AND NOT published
	`, record.stream, record.consumer, record.sequence, record.hash,
		record.reason, record.dlq, record.subject, record.evidence)
	if err != nil {
		return fmt.Errorf("persist DLQ publish attempt fence: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrDispositionConflict
	}
	return nil
}

// confirm records a broker-verified, stream/subject-matched DLQ message.
// It is monotonic and idempotent. A source ACK still requires independent
// re-verification that the broker record remains retained.
func (j *DispositionJournal) confirm(ctx context.Context, record dispositionRecord) error {
	if _, err := ValidateDispositionJournal(j); err != nil {
		return err
	}
	tag, err := j.pool.Exec(ctx, `
		UPDATE poc_dlq_dispositions SET
			published=TRUE,
			published_at=COALESCE(published_at,clock_timestamp())
		WHERE source_stream=$1 AND source_consumer=$2 AND source_sequence=$3
		  AND delivery_hash=$4 AND reason=$5 AND dlq_stream=$6
		  AND dlq_subject=$7 AND evidence=$8
	`, record.stream, record.consumer, record.sequence, record.hash,
		record.reason, record.dlq, record.subject, record.evidence)
	if err != nil {
		return fmt.Errorf("confirm verified DLQ disposition: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrDispositionConflict
	}
	return nil
}
