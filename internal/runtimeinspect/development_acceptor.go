package runtimeinspect

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

const developmentAcceptPath = "/internal/v2/run-intents:accept"
const maxAcceptBodyBytes = runintent.MaxExecutionInputBytes + 4096

type executionInputStore interface {
	Get(context.Context, string, string) (runintent.Intent, error)
	GetExecutionInput(context.Context, string, string) ([]byte, error)
}

// DevelopmentAcceptor is deliberately not wired into a service or production
// scheduler. It exercises the pinned Runtime v2 development contract using
// the same verified TLS 1.3 workload transport as read-only Inspect. It is
// not a policy issuer, protected-effect permit or Temporal start client.
type DevelopmentAcceptor struct {
	client *Client
	store  executionInputStore
}

func NewDevelopmentAcceptor(client *Client, store executionInputStore) (*DevelopmentAcceptor, error) {
	if client == nil || client.client == nil || client.base == "" || store == nil {
		return nil, ErrInvalidConfig
	}
	return &DevelopmentAcceptor{client: client, store: store}, nil
}

type principalAcceptanceWire struct {
	Version        string `json:"version"`
	ProjectID      string `json:"project_id"`
	SubjectID      string `json:"subject_id"`
	ActorID        string `json:"actor_id"`
	PolicyRevision string `json:"policy_revision"`
	ConfigDigest   string `json:"config_digest"`
}

type acceptanceWire struct {
	TenantID       string                  `json:"tenant_id"`
	RunIntentID    string                  `json:"run_intent_id"`
	RequestDigest  string                  `json:"request_digest"`
	AgentID        string                  `json:"agent_id"`
	AgentReleaseID string                  `json:"agent_release_id"`
	SessionID      string                  `json:"session_id"`
	Principal      principalAcceptanceWire `json:"principal_context"`
}

// buildAcceptanceBody embeds the validated original JSON bytes directly.
// encoding/json would compact RawMessage and escape HTML characters. The
// exact-byte digest belongs to ACP; Runtime independently normalizes its
// JSON input for replay comparison under the current development contract.
func buildAcceptanceBody(intent runintent.Intent, input []byte) ([]byte, error) {
	if err := runintent.VerifyExecutionInput(intent, input); err != nil {
		return nil, err
	}
	s := intent.PrincipalSnapshot
	if err := s.ValidateForProject(intent.ProjectID); err != nil {
		return nil, err
	}
	header, err := json.Marshal(acceptanceWire{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest,
		AgentID: intent.AgentID, AgentReleaseID: intent.ReleaseID, SessionID: intent.SessionID,
		Principal: principalAcceptanceWire{
			Version: s.Version, ProjectID: s.ProjectID, SubjectID: s.SubjectID,
			ActorID: s.ActorID, PolicyRevision: s.PolicyRevision, ConfigDigest: s.ConfigDigest,
		},
	})
	if err != nil {
		return nil, ErrInvalidRequest
	}
	body := append(header[:len(header)-1], []byte(`,"input":`)...)
	body = append(body, input...)
	body = append(body, '}')
	if len(body) > maxAcceptBodyBytes {
		return nil, ErrInvalidRequest
	}
	return body, nil
}

// Accept reads the committed claim and exact input from ACP storage, never
// a user-supplied snapshot or in-memory task payload. Runtime's Run and
// Workflow IDs are accepted only from a correlated authenticated receipt.
func (a *DevelopmentAcceptor) Accept(ctx context.Context, claimed runintent.Intent) (runintent.DispatchOutcome, error) {
	if a == nil || a.client == nil || a.store == nil {
		return runintent.DispatchOutcome{}, ErrInvalidConfig
	}
	if claimed.Validate() != nil || claimed.Status != runintent.Dispatching ||
		!claimed.LeaseExpiresAt.After(time.Now()) {
		return runintent.DispatchOutcome{}, ErrNotDispatchable
	}
	persisted, err := a.store.Get(ctx, claimed.TenantID, claimed.ID)
	if err != nil {
		return runintent.DispatchOutcome{}, err
	}
	if !persisted.LeaseExpiresAt.Equal(claimed.LeaseExpiresAt) {
		return runintent.DispatchOutcome{}, ErrNotDispatchable
	}
	// PostgreSQL timestamps may differ in location/monotonic metadata.
	claimed.LeaseExpiresAt = persisted.LeaseExpiresAt
	if persisted != claimed {
		return runintent.DispatchOutcome{}, ErrNotDispatchable
	}
	scope := InspectRequest{TenantID: persisted.TenantID, RunIntentID: persisted.ID, RequestDigest: persisted.RequestDigest}
	if err := scope.Validate(); err != nil {
		return runintent.DispatchOutcome{}, err
	}
	input, err := a.store.GetExecutionInput(ctx, persisted.TenantID, persisted.ID)
	if err != nil {
		return runintent.DispatchOutcome{}, err
	}
	body, err := buildAcceptanceBody(persisted, input)
	if err != nil {
		return runintent.DispatchOutcome{}, err
	}
	if !persisted.LeaseExpiresAt.After(time.Now()) {
		return runintent.DispatchOutcome{}, ErrNotDispatchable
	}
	requestCtx, cancel := context.WithDeadline(ctx, persisted.LeaseExpiresAt)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, a.client.base+developmentAcceptPath, bytes.NewReader(body))
	if err != nil {
		return runintent.DispatchOutcome{}, ErrInvalidRequest
	}
	req.GetBody = nil // never authorize automatic replay of this POST
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.client.Do(req)
	if err != nil {
		return runintent.DispatchOutcome{}, ErrUnavailable
	}
	defer resp.Body.Close()
	outcome := runintent.DispatchOutcome{
		TenantID: scope.TenantID, RunIntentID: scope.RunIntentID, RequestDigest: scope.RequestDigest,
	}
	switch resp.StatusCode {
	case http.StatusConflict:
		// A conflict from the exact authenticated Runtime must never become
		// a subsequent FOUND on a weaker lookup. Quarantine immediately.
		outcome.Kind = runintent.DispatchConflict
		return outcome, nil
	case http.StatusOK, http.StatusCreated:
	default:
		return runintent.DispatchOutcome{}, ErrUnavailable
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return runintent.DispatchOutcome{}, ErrInvalidResponse
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxResponseBytes || !utf8.Valid(raw) {
		return runintent.DispatchOutcome{}, ErrInvalidResponse
	}
	receipt, err := parseInspectResponse(raw, scope)
	if err != nil || receipt.Status != Found {
		return runintent.DispatchOutcome{}, ErrInvalidResponse
	}
	fields, err := uniqueObject(raw)
	if err != nil || (string(fields["created"]) == "true") != (resp.StatusCode == http.StatusCreated) {
		return runintent.DispatchOutcome{}, ErrInvalidResponse
	}
	outcome.Kind = runintent.DispatchAccepted
	outcome.RunID, outcome.WorkflowID = receipt.RunID, receipt.WorkflowID
	return outcome, nil
}

var _ dispatchAcceptor = (*DevelopmentAcceptor)(nil)
