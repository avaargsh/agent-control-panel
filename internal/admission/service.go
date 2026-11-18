// Package admission provides the internal ACP-owned RunIntent admission
// boundary. A trusted identity/policy resolver must be injected by the host;
// this package does not authenticate HTTP clients or dispatch Runtime Runs.
package admission

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

var (
	ErrInvalidConfig = errors.New("RunIntent admission is not configured")
	ErrInvalidGrant  = errors.New("RunIntent admission grant does not match request")
)

// Target contains requested resource selectors, not authenticated identity.
type Target struct {
	TenantID  string
	ProjectID string
	AgentID   string
	ReleaseID string
	SessionID string
}

// Request intentionally has no principal, actor, policy, config or Runtime
// identity fields. RequestDigest is a proposed selector: Resolver must
// independently verify it against the canonical immutable request.
type Request struct {
	Target         Target
	IdempotencyKey string
	RequestDigest  string
	inputBound     bool // set only after ACP computes the exact input digest
}

// Grant is an internal assertion from the configured trusted ACP resolver,
// never decoded from user JSON. It is admission evidence, not a Guard permit.
type Grant struct {
	Target        Target
	RequestDigest string
	PrincipalID   string
	Snapshot      runintent.PrincipalSnapshot
}

// Resolver authenticates the caller using trusted context, checks access to
// every requested resource and resolves immutable release/config/policy
// evidence. It independently validates the canonical request digest. Return
// an error for denied or indeterminate authorization; no fallback exists.
type Resolver interface {
	Resolve(context.Context, Request) (Grant, error)
}

type Store interface {
	Create(context.Context, runintent.Intent, runpg.Event) (runintent.Intent, bool, error)
}

type inputStore interface {
	CreateWithInput(context.Context, runintent.Intent, runpg.Event, []byte) (runintent.Intent, bool, error)
}

type Service struct {
	store    Store
	resolver Resolver
}

func New(store Store, resolver Resolver) *Service {
	return &Service{store: store, resolver: resolver}
}

// Admit resolves authorization on every request, including idempotent
// replays. Repository.Create atomically commits identity, snapshot and
// Outbox or returns the original matching intent. This does not persist
// raw task input, start a Run, or grant protected execution.
func (s *Service) Admit(ctx context.Context, req Request) (runintent.Intent, bool, error) {
	req.inputBound = false
	return s.admit(ctx, req, nil)
}

// AdmitWithInput computes the digest over the exact request bytes before
// policy resolution. An optional supplied digest must match. The policy
// authority must authorize this bound request; raw bytes stay out of events.
// Never fall back to legacy storage when the input-capable store is missing.
func (s *Service) AdmitWithInput(ctx context.Context, req Request, raw []byte) (runintent.Intent, bool, error) {
	if s == nil || s.resolver == nil {
		return runintent.Intent{}, false, ErrInvalidConfig
	}
	if _, ok := s.store.(inputStore); !ok {
		return runintent.Intent{}, false, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return runintent.Intent{}, false, err
	}
	if len(raw) > runintent.MaxExecutionInputBytes {
		return runintent.Intent{}, false, runintent.ErrInvalidExecutionInput
	}
	input := bytes.Clone(raw)
	digest, err := runintent.ExecutionInputDigest(runintent.Intent{
		TenantID: req.Target.TenantID, ProjectID: req.Target.ProjectID,
		AgentID: req.Target.AgentID, ReleaseID: req.Target.ReleaseID,
		SessionID: req.Target.SessionID, IdempotencyKey: req.IdempotencyKey,
	}, input)
	if err != nil {
		return runintent.Intent{}, false, err
	}
	if req.RequestDigest != "" && req.RequestDigest != digest {
		return runintent.Intent{}, false, runintent.ErrExecutionInputMismatch
	}
	req.RequestDigest = digest
	req.inputBound = true
	return s.admit(ctx, req, input)
}

func (s *Service) admit(ctx context.Context, req Request, input []byte) (runintent.Intent, bool, error) {
	if s == nil || s.store == nil || s.resolver == nil {
		return runintent.Intent{}, false, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return runintent.Intent{}, false, err
	}
	// Reuse domain validation for selector shape without treating any
	// placeholder as an authenticated principal or persisting it.
	candidate := runintent.Intent{
		ID: "validation-only", PrincipalID: "validation-only",
		TenantID: req.Target.TenantID, ProjectID: req.Target.ProjectID,
		AgentID: req.Target.AgentID, ReleaseID: req.Target.ReleaseID, SessionID: req.Target.SessionID,
		IdempotencyKey: req.IdempotencyKey, RequestDigest: req.RequestDigest,
		Version: 1, Status: runintent.Pending,
	}
	if err := candidate.Validate(); err != nil {
		return runintent.Intent{}, false, err
	}
	grant, err := s.resolver.Resolve(ctx, req)
	if err != nil {
		return runintent.Intent{}, false, err
	}
	if grant.Target != req.Target || grant.RequestDigest != req.RequestDigest {
		return runintent.Intent{}, false, ErrInvalidGrant
	}
	if err := grant.Snapshot.ValidateForProject(grant.Target.ProjectID); err != nil {
		return runintent.Intent{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return runintent.Intent{}, false, err
	}
	candidate.ID, err = newID()
	if err != nil {
		return runintent.Intent{}, false, err
	}
	candidate.PrincipalID = grant.PrincipalID
	candidate.PrincipalSnapshot = grant.Snapshot
	if err := candidate.Validate(); err != nil {
		return runintent.Intent{}, false, err
	}
	eventID, err := newID()
	if err != nil {
		return runintent.Intent{}, false, err
	}
	payload, err := json.Marshal(map[string]string{"run_intent_id": candidate.ID})
	if err != nil {
		return runintent.Intent{}, false, err
	}
	event := runpg.Event{
		ID: eventID, Producer: "agent-control-panel", Type: "agent.run-intent.created",
		SchemaVersion: 1, TenantID: candidate.TenantID, AggregateType: "run_intent",
		AggregateID: candidate.ID, AggregateVersion: candidate.Version,
		OccurredAt: time.Now().UTC(), CorrelationID: candidate.ID, Payload: payload,
	}
	if input != nil {
		return s.store.(inputStore).CreateWithInput(ctx, candidate, event, input)
	}
	return s.store.Create(ctx, candidate, event)
}

// IDs here identify ACP-owned intents and Outbox events only.
func newID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate admission identity: %w", err)
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]), nil
}
