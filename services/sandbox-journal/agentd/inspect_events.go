package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	InspectSchema    = "acp.agentd-inspect-event/v1"
	InspectDomain    = "acp.agentd-inspect-event/v1\x00"
	maxInspectEvents = 10000
)

// InspectEvent is an original source-owned observation, not a proposed
// execution outcome. journal_version is the signed ordinal of the INSPECT
// event stream; the distinct OS Wait terminal has its own source revision.
type InspectEvent struct {
	Schema            string `json:"schema"`
	Source            string `json:"source"`
	Ref               Ref    `json:"ref"`
	ObservedAt        string `json:"observed_at"`
	InspectCount      uint64 `json:"inspect_count"`
	JournalVersion    uint64 `json:"journal_version"`
	PreviousDigest    string `json:"previous_digest"`
	State             string `json:"state"`
	ExitReceiptDigest string `json:"exit_receipt_digest,omitempty"`
	NextAction        string `json:"next_action"`
	DispatchCount     uint64 `json:"dispatch_count"`
	Replayed          bool   `json:"replayed"`
}

type JournaledInspection struct {
	Result    Result
	Event     InspectEvent
	Payload   []byte
	Signature []byte
	Digest    string
}

const selectInspectChain = `SELECT inspect_count,journal_version,payload,signature,payload_digest,previous_digest
	FROM public.sandbox_agentd_inspect_events
	WHERE tenant_id=$1 AND sandbox_uid=$2 AND command_id=$3 AND attempt_id=$4
	ORDER BY inspect_count LIMIT 10001`

func readInspectRows(ctx context.Context, tx pgx.Tx, ref Ref) ([]JournaledInspection, error) {
	rows, err := tx.Query(ctx, selectInspectChain, ref.TenantID, ref.SandboxUID, ref.CommandID, ref.AttemptID)
	if err != nil {
		return nil, ErrUnverified
	}
	defer rows.Close()
	out := make([]JournaledInspection, 0)
	for rows.Next() {
		var i, version int64
		var previous string
		var record JournaledInspection
		if err := rows.Scan(&i, &version, &record.Payload, &record.Signature, &record.Digest, &previous); err != nil {
			return nil, ErrUnverified
		}
		if i <= 0 || version != i || len(out) >= maxInspectEvents ||
			!decodeInspect(record.Payload, &record.Event) ||
			record.Event.InspectCount != uint64(i) || record.Event.JournalVersion != uint64(version) ||
			record.Event.PreviousDigest != previous {
			return nil, ErrUnverified
		}
		out = append(out, record)
	}
	if rows.Err() != nil {
		return nil, ErrUnverified
	}
	return out, nil
}

func decodeInspect(raw []byte, dst *InspectEvent) bool {
	if len(raw) == 0 || len(raw) > 8192 || json.Unmarshal(raw, dst) != nil {
		return false
	}
	canonical, err := json.Marshal(dst)
	return err == nil && bytes.Equal(canonical, raw)
}

// VerifyInspectChain independently authenticates the COMPLETE source
// sequence, including each previous raw payload digest. Source event count
// gaps, replayed/renumbered rows and fabricated terminal claims are denied.
// It never grants a re-dispatch, Permit or provider release.
func VerifyInspectChain(events []JournaledInspection, expected Ref, key ed25519.PublicKey, now time.Time) error {
	if !expected.valid() || len(key) != ed25519.PublicKeySize ||
		len(events) == 0 || len(events) > maxInspectEvents {
		return ErrUnverified
	}
	previous := ""
	var priorTime time.Time
	for i, row := range events {
		var event InspectEvent
		if !decodeInspect(row.Payload, &event) || event != row.Event ||
			digest(row.Payload) != row.Digest ||
			len(row.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(key, append([]byte(InspectDomain), row.Payload...), row.Signature) ||
			event.Schema != InspectSchema || event.Source != "agentd.inspect" ||
			event.Ref != expected || event.InspectCount != uint64(i+1) ||
			event.JournalVersion != event.InspectCount ||
			event.PreviousDigest != previous || event.NextAction != Hold ||
			event.DispatchCount != 1 || event.Replayed {
			return ErrUnverified
		}
		t, err := time.Parse(time.RFC3339Nano, event.ObservedAt)
		if err != nil || t.After(now.Add(10*time.Second)) || (!priorTime.IsZero() && t.Before(priorTime)) {
			return ErrUnverified
		}
		switch event.State {
		case Unknown:
			if event.ExitReceiptDigest != "" {
				return ErrUnverified
			}
		case Exited, FailedConfirmed:
			if len(event.ExitReceiptDigest) != len("sha256:")+64 ||
				!bytes.HasPrefix([]byte(event.ExitReceiptDigest), []byte("sha256:")) {
				return ErrUnverified
			}
			for _, c := range event.ExitReceiptDigest[len("sha256:"):] {
				if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
					return ErrUnverified
				}
			}
		default:
			return ErrUnverified
		}
		previous = row.Digest
		priorTime = t
	}
	return nil
}

// InspectHead must be pinned by an independent trusted consumer (e.g. ACP
// Run evidence verifier). A self-supplied head cannot detect a truncated
// suffix of an otherwise valid signature/hash chain.
type InspectHead struct {
	InspectCount   uint64
	JournalVersion uint64
	Digest         string
}

func VerifyInspectAtHead(events []JournaledInspection, expected Ref,
	key ed25519.PublicKey, now time.Time, trustedHead InspectHead) error {
	if err := VerifyInspectChain(events, expected, key, now); err != nil {
		return err
	}
	last := events[len(events)-1]
	if last.Event.InspectCount != trustedHead.InspectCount ||
		last.Event.JournalVersion != trustedHead.JournalVersion ||
		last.Digest != trustedHead.Digest {
		return ErrUnverified
	}
	return nil
}

// LoadInspectChain is a fresh, read-only source query which never trusts an
// inspector's requested count, last event or claimed status. It checks the
// original immutable attempt, then every owner-signed journal event.
func LoadInspectChain(ctx context.Context, db *pgxpool.Pool, expected Ref,
	key ed25519.PublicKey, now time.Time) ([]JournaledInspection, error) {
	if db == nil || !expected.valid() {
		return nil, ErrUnverified
	}
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, ErrUnverified
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	events, err := loadInspectChainTx(ctx, tx, expected, key, now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, ErrUnverified
	}
	return events, nil
}

// loadInspectChainTx verifies the complete source history inside a caller-owned
// transaction. The HTTP reader uses this to keep tenant GUC, RLS, attempt,
// terminal and Inspect rows in one repeatable-read snapshot.
func loadInspectChainTx(ctx context.Context, tx pgx.Tx, expected Ref,
	key ed25519.PublicKey, now time.Time) ([]JournaledInspection, error) {
	if tx == nil || !expected.valid() || len(key) != ed25519.PublicKeySize {
		return nil, ErrUnverified
	}
	if err := readOriginal(ctx, tx, expected); err != nil {
		return nil, err
	}
	events, err := readInspectRows(ctx, tx, expected)
	if err != nil {
		return nil, err
	}
	if err := VerifyInspectChain(events, expected, key, now); err != nil {
		return nil, err
	}
	return events, nil
}

// InspectAndJournal is a source-side opt-in candidate. It checks the original
// identity and real signed OS Wait receipt, then atomically commits a fresh
// signed inspection event with a monotonic ordinal and hash of the previous
// event. A missing Wait means a signed UNKNOWN/HOLD event, not a guessed exit.
//
// This source writer currently requires owner-only CI credentials. No Guard
// issuer/PEP or production attempt-registration privilege is implemented.
func InspectAndJournal(ctx context.Context, db *pgxpool.Pool, ref Ref,
	public ed25519.PublicKey, private ed25519.PrivateKey) (JournaledInspection, error) {
	var blockedEvent JournaledInspection
	blockedEvent.Result = blocked(ref)
	if db == nil || !ref.valid() || len(public) != ed25519.PublicKeySize ||
		len(private) != ed25519.PrivateKeySize ||
		!bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		return blockedEvent, ErrUnverified
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return blockedEvent, ErrUnverified
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	// SERIALIZE all inspections of this original attempt even if two AgentD
	// workers concurrently inspect after an ACK loss. The attempt is immutable;
	// a source row lock is not an attempt to update or re-dispatch it.
	locked, err := scanOriginal(tx.QueryRow(ctx, selectOriginal+" FOR UPDATE",
		ref.TenantID, ref.SandboxUID, ref.CommandID, ref.AttemptID))
	if errors.Is(err, pgx.ErrNoRows) {
		return blockedEvent, ErrNotFound
	}
	if err != nil {
		return blockedEvent, ErrUnverified
	}
	if locked != ref {
		return blockedEvent, ErrMismatch
	}
	prior, err := readInspectRows(ctx, tx, ref)
	if err != nil {
		return blockedEvent, err
	}
	if len(prior) > 0 {
		if err := VerifyInspectChain(prior, ref, public, time.Now().UTC()); err != nil {
			return blockedEvent, err
		}
	}
	var raw, sig []byte
	var terminalDigest string
	err = tx.QueryRow(ctx, `SELECT payload,signature,payload_digest
		FROM public.sandbox_agentd_terminal_receipts
		WHERE tenant_id=$1 AND sandbox_uid=$2 AND command_id=$3 AND attempt_id=$4`,
		ref.TenantID, ref.SandboxUID, ref.CommandID, ref.AttemptID).
		Scan(&raw, &sig, &terminalDigest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return blockedEvent, ErrUnverified
	}
	if err == nil {
		terminal, verifyErr := verifyTerminal(raw, sig, terminalDigest, ref, public)
		if verifyErr != nil {
			return blockedEvent, verifyErr
		}
		blockedEvent.Result.State = terminal.Status
		blockedEvent.Result.ExitReceiptDigest = terminalDigest
		blockedEvent.Result.ReceiptPayload = raw
		blockedEvent.Result.ReceiptSignature = sig
	}
	next := uint64(len(prior) + 1)
	previous := ""
	if len(prior) > 0 {
		previous = prior[len(prior)-1].Digest
	}
	event := InspectEvent{
		Schema: InspectSchema, Source: "agentd.inspect", Ref: ref,
		ObservedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		InspectCount: next, JournalVersion: next,
		PreviousDigest: previous, State: blockedEvent.Result.State,
		ExitReceiptDigest: blockedEvent.Result.ExitReceiptDigest,
		NextAction:        Hold, DispatchCount: 1, Replayed: false,
	}
	eventRaw, err := json.Marshal(event)
	if err != nil || len(eventRaw) > 8192 {
		return blockedEvent, ErrUnverified
	}
	eventSig := ed25519.Sign(private, append([]byte(InspectDomain), eventRaw...))
	eventDigest := digest(eventRaw)
	if _, err := tx.Exec(ctx, `INSERT INTO public.sandbox_agentd_inspect_events
		(tenant_id,sandbox_uid,command_id,attempt_id,inspect_count,journal_version,
		payload,signature,payload_digest,previous_digest)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		ref.TenantID, ref.SandboxUID, ref.CommandID, ref.AttemptID,
		next, next, eventRaw, eventSig, eventDigest, previous); err != nil {
		return blockedEvent, ErrUnverified
	}
	if err := tx.Commit(ctx); err != nil {
		return blockedEvent, ErrUnverified
	}
	blockedEvent.Result.OriginalProcess = inspectLinuxOriginalProcess(ref)
	return JournaledInspection{
		Result: blockedEvent.Result, Event: event, Payload: eventRaw,
		Signature: eventSig, Digest: eventDigest,
	}, nil
}
