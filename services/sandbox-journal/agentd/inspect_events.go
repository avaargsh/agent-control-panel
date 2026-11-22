package agentd

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const InspectSchema = "acp.agentd-inspect-event/v1"
const InspectDomain = "acp.agentd-inspect-event/v1\x00"

// InspectEvent is a source-owned, signed observation. Its journal_version
// belongs exclusively to the AgentD inspection stream, independent from the
// OS Wait terminal's own local revision.
type InspectEvent struct {
	Schema          string `json:"schema"`
	Source          string `json:"source"`
	Ref             Ref    `json:"ref"`
	ObservedAt      string `json:"observed_at"`
	InspectCount    uint64 `json:"inspect_count"`
	JournalVersion  uint64 `json:"journal_version"`
	PreviousDigest  string `json:"previous_digest"`
	State           string `json:"state"`
	ExitReceiptDigest string `json:"exit_receipt_digest,omitempty"`
	NextAction      string `json:"next_action"`
	DispatchCount   uint64 `json:"dispatch_count"`
	Replayed        bool   `json:"replayed"`
}

type JournaledInspection struct {
	Result Result
	Event InspectEvent
	Payload []byte
	Signature []byte
	Digest string
}

// InspectAndJournal must persist a fresh signed source event atomically with
// its predecessor hash after authoritative terminal verification.
// Placeholder for behavior-first RED tests; it does NOT enable dispatch.
func InspectAndJournal(ctx context.Context, db *pgxpool.Pool, ref Ref,
	public ed25519.PublicKey, private ed25519.PrivateKey) (JournaledInspection,error) {
	result,err:=InspectCommand(ctx,db,ref,public)
	return JournaledInspection{Result:result},err
}

// VerifyInspectChain is a separately trusted offline verifier of the
// recorded, source-owned inspection sequence. Stub for TDD RED.
func VerifyInspectChain(events []JournaledInspection, expected Ref, key ed25519.PublicKey, now time.Time) error {
	return nil
}

// LoadInspectChain will verify every source-owned durable event from a new DB
// connection and reject missing/tampered source history.
func LoadInspectChain(ctx context.Context, db *pgxpool.Pool, expected Ref,
	key ed25519.PublicKey, now time.Time) ([]JournaledInspection, error) {
	return nil, ErrUnverified
}
