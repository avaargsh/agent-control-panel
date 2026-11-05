// Package jetstreampoc is an experimental real-broker adapter.
// It is not a production broker implementation or an authorization boundary.
package jetstreampoc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/avaargsh/agent-control-panel/internal/inboxtransport"
	"github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/nats-io/nats.go/jetstream"
)

const maxPOCEnvelopeBytes = 256 * 1024

var ErrUntrustedBrokerDelivery = errors.New("invalid JetStream POC source, metadata or envelope")

// Config is an exact POC allowlist. The source stream/consumer/subject are
// verified against server-provided JetStream message metadata before storage.
type Config struct {
	ConsumerName   string
	SourceStream   string
	SourceConsumer string
	SourceSubject  string
	DLQStream      string
	DLQSubject     string
}

// DLQEvidence is intentionally metadata-only: full conflicting envelopes are
// retained by ACP PostgreSQL. A broker DLQ record never grants replay rights.
type DLQEvidence struct {
	Version        int    `json:"version"`
	Reason         string `json:"reason"`
	SourceStream   string `json:"source_stream"`
	SourceConsumer string `json:"source_consumer"`
	SourceSubject  string `json:"source_subject"`
	SourceSequence uint64 `json:"source_sequence"`
	DeliveryHash   string `json:"delivery_sha256"`
}

// Delivery bridges the real JetStream per-message ACK and confirmed DLQ PubAck
// to the ACP Inbox transport-neutral settlement gate. The publish+ACK pair
// is deliberately NOT an atomic transaction and does not provide lifetime
// DLQ deduplication outside JetStream's finite duplicate window.
type Delivery struct {
	js   jetstream.JetStream
	msg  jetstream.Msg
	cfg  Config
	meta *jetstream.MsgMetadata
	journal *DispositionJournal
}

func NewDelivery(js jetstream.JetStream, msg jetstream.Msg, cfg Config, journal *DispositionJournal) (*Delivery, error) {
	if _, err := ValidateDispositionJournal(journal); err != nil {
		return nil, err
	}
	if js == nil || msg == nil ||
		cfg.ConsumerName == "" || cfg.SourceStream == "" || cfg.SourceConsumer == "" ||
		cfg.SourceSubject == "" || cfg.DLQStream == "" || cfg.DLQSubject == "" ||
		msg.Subject() != cfg.SourceSubject {
		return nil, ErrUntrustedBrokerDelivery
	}
	meta, err := msg.Metadata()
	if err != nil || meta == nil ||
		meta.Stream != cfg.SourceStream || meta.Consumer != cfg.SourceConsumer ||
		meta.Sequence.Stream == 0 {
		return nil, ErrUntrustedBrokerDelivery
	}
	return &Delivery{js: js, msg: msg, cfg: cfg, meta: meta, journal: journal}, nil
}

func (d *Delivery) Ack(ctx context.Context) error {
	if d == nil {
		return ErrUntrustedBrokerDelivery
	}
	return d.msg.DoubleAck(ctx)
}

// DeadLetter must verify a retained, immutable DLQ record before source ACK.
// A PostgreSQL disposition intent and one-record-per-subject JetStream stream
// are both necessary; finite Nats-Msg-Id dedup alone cannot enforce this.
func (d *Delivery) DeadLetter(ctx context.Context, reason string) error {
	if d == nil || (reason != inboxtransport.ReasonEventIDConflict && reason != inboxtransport.ReasonQuarantined) {
		return ErrUntrustedBrokerDelivery
	}
	if _, err := ValidateDispositionJournal(d.journal); err != nil {
		return err
	}
	stream, err := d.js.Stream(ctx, d.cfg.DLQStream)
	if err != nil {
		return fmt.Errorf("resolve expected DLQ stream: %w", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return fmt.Errorf("verify expected DLQ stream: %w", err)
	}
	if info.Config.Discard != jetstream.DiscardNew ||
		!info.Config.DiscardNewPerSubject || info.Config.MaxMsgsPerSubject != 1 ||
		info.Config.MaxAge != 0 || info.Config.Retention != jetstream.LimitsPolicy ||
		len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != d.cfg.DLQSubject+".*" {
		return ErrUntrustedBrokerDelivery
	}
	bodyHash := sha256.Sum256(d.msg.Data())
	evidence := DLQEvidence{
		Version:        1,
		Reason:         reason,
		SourceStream:   d.meta.Stream,
		SourceConsumer: d.meta.Consumer,
		SourceSubject:  d.msg.Subject(),
		SourceSequence: d.meta.Sequence.Stream,
		DeliveryHash:   fmt.Sprintf("%x", bodyHash),
	}
	data, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("encode DLQ disposition: %w", err)
	}
	keyInput := []byte(d.meta.Stream + "\x00" + d.meta.Consumer + "\x00" +
		strconv.FormatUint(d.meta.Sequence.Stream, 10) + "\x00" + reason + "\x00" + evidence.DeliveryHash)
	key := sha256.Sum256(keyInput)
	dispositionID := fmt.Sprintf("%x", key)
	subject := d.cfg.DLQSubject + "." + dispositionID
	record := dispositionRecord{
		stream: d.meta.Stream, consumer: d.meta.Consumer, sequence: int64(d.meta.Sequence.Stream),
		hash: evidence.DeliveryHash, reason: reason, dlq: d.cfg.DLQStream,
		subject: subject, evidence: data,
	}
	confirmed, err := d.journal.ensure(ctx, record)
	if err != nil {
		return err
	}
	existing, lookupErr := stream.GetLastMsgForSubject(ctx, subject)
	if lookupErr == nil {
		if existing.Subject != subject || !bytes.Equal(existing.Data, data) {
			return ErrDLQEvidenceConflict
		}
	} else {
		if !errors.Is(lookupErr, jetstream.ErrMsgNotFound) {
			return fmt.Errorf("inspect durable DLQ evidence: %w", lookupErr)
		}
		if confirmed {
			return ErrDLQEvidenceMissing
		}
		pub, publishErr := d.js.Publish(ctx, subject, data,
			jetstream.WithMsgID(dispositionID),
			jetstream.WithExpectStream(d.cfg.DLQStream))
		if publishErr != nil {
			// Concurrent duplicate is acceptable only when the broker
			// actually retained the identical immutable disposition.
			existing, err = stream.GetLastMsgForSubject(ctx, subject)
			if err != nil {
				return fmt.Errorf("publish confirmed JetStream DLQ evidence: %w", publishErr)
			}
		} else if pub == nil || pub.Stream != d.cfg.DLQStream || pub.Sequence == 0 {
			return ErrUntrustedBrokerDelivery
		}
		existing, err = stream.GetLastMsgForSubject(ctx, subject)
		if err != nil {
			return fmt.Errorf("verify published DLQ evidence: %w", err)
		}
		if existing.Subject != subject || !bytes.Equal(existing.Data, data) {
			return ErrDLQEvidenceConflict
		}
	}
	if err := d.journal.confirm(ctx, record); err != nil {
		return err
	}
	if err := d.msg.DoubleAck(ctx); err != nil {
		return fmt.Errorf("source ACK uncertain after verified DLQ journal: %w", err)
	}
	return nil
}

// HandleMessage reads only an allowed JetStream delivery and passes its
// canonical envelope to the existing transactional PostgreSQL Inbox receiver.
func HandleMessage(ctx context.Context, receiver inboxtransport.Receiver, js jetstream.JetStream, msg jetstream.Msg, cfg Config, journal *DispositionJournal) error {
	delivery, err := NewDelivery(js, msg, cfg, journal)
	if err != nil {
		return err
	}
	raw := msg.Data()
	if len(raw) == 0 || len(raw) > maxPOCEnvelopeBytes {
		return ErrUntrustedBrokerDelivery
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var event postgres.Event
	if err := dec.Decode(&event); err != nil {
		return fmt.Errorf("%w: %v", ErrUntrustedBrokerDelivery, err)
	}
	var trailer json.RawMessage
	if err := dec.Decode(&trailer); err != io.EOF {
		return ErrUntrustedBrokerDelivery
	}
	return inboxtransport.HandleDelivery(ctx, receiver, delivery, cfg.ConsumerName, event)
}
