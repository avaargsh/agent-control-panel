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
}

func NewDelivery(js jetstream.JetStream, msg jetstream.Msg, cfg Config) (*Delivery, error) {
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
	return &Delivery{js: js, msg: msg, cfg: cfg, meta: meta}, nil
}

func (d *Delivery) Ack(ctx context.Context) error {
	if d == nil {
		return ErrUntrustedBrokerDelivery
	}
	return d.msg.DoubleAck(ctx)
}

// DeadLetter must first receive a positive publish acknowledgement from the
// specifically configured DLQ stream. Only then can source DoubleAck run.
// A missing DLQ, PubAck timeout, wrong stream or failed DoubleAck is an error.
func (d *Delivery) DeadLetter(ctx context.Context, reason string) error {
	if d == nil || (reason != inboxtransport.ReasonEventIDConflict && reason != inboxtransport.ReasonQuarantined) {
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
	// Stable within the POC test stream. A production adapter requires a
	// unique durable disposition journal outside a rolling dedup window.
	keyInput := []byte(d.meta.Stream + "\x00" +
		strconv.FormatUint(d.meta.Sequence.Stream, 10) + "\x00" + reason + "\x00" + evidence.DeliveryHash)
	key := sha256.Sum256(keyInput)
	pub, err := d.js.Publish(ctx, d.cfg.DLQSubject, data,
		jetstream.WithMsgID(fmt.Sprintf("%x", key)),
		jetstream.WithExpectStream(d.cfg.DLQStream))
	if err != nil {
		return fmt.Errorf("publish confirmed JetStream DLQ evidence: %w", err)
	}
	if pub == nil || pub.Stream != d.cfg.DLQStream || pub.Sequence == 0 {
		return ErrUntrustedBrokerDelivery
	}
	if err := d.msg.DoubleAck(ctx); err != nil {
		return fmt.Errorf("source ACK uncertain after DLQ PubAck: %w", err)
	}
	return nil
}

// HandleMessage reads only an allowed JetStream delivery and passes its
// canonical envelope to the existing transactional PostgreSQL Inbox receiver.
func HandleMessage(ctx context.Context, receiver inboxtransport.Receiver, js jetstream.JetStream, msg jetstream.Msg, cfg Config) error {
	delivery, err := NewDelivery(js, msg, cfg)
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
