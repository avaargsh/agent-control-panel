package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/domain"
)

type RunRepository interface {
	// CreateRun must atomically claim (tenant, operation, idempotencyKey), persist
	// the Session/Run and append the RunCreated outbox event.
	CreateRun(ctx context.Context, run domain.Run, idempotencyKey, requestHash string) (domain.Run, bool, error)
	GetRun(ctx context.Context, tenantID, runID string) (domain.Run, error)
	TransitionRun(ctx context.Context, tenantID, runID string, expectedVersion int64, target domain.RunStatus, reason string, at time.Time) (domain.Run, error)
}

type CreateRunCommand struct {
	TenantID       string          `json:"tenantId"`
	AgentID        string          `json:"agentId"`
	ReleaseID      string          `json:"releaseId"`
	SessionID      string          `json:"sessionId,omitempty"`
	Input          json.RawMessage `json:"input,omitempty"`
	IdempotencyKey string          `json:"-"`
}

type RunService struct {
	repo  RunRepository
	now   func() time.Time
	newID func() (string, error)
}

func NewRunService(repo RunRepository) *RunService {
	return &RunService{repo: repo, now: time.Now, newID: domain.NewID}
}

func (s *RunService) Create(ctx context.Context, cmd CreateRunCommand) (domain.Run, bool, error) {
	cmd.IdempotencyKey = strings.TrimSpace(cmd.IdempotencyKey)
	if cmd.IdempotencyKey == "" || len(cmd.IdempotencyKey) > 255 {
		return domain.Run{}, false, fmt.Errorf("%w: Idempotency-Key must contain 1..255 characters", domain.ErrInvalidInput)
	}
	requestHash, err := hashCreateCommand(cmd)
	if err != nil {
		return domain.Run{}, false, err
	}

	sessionID := cmd.SessionID
	if sessionID == "" {
		sessionID, err = s.newID()
		if err != nil {
			return domain.Run{}, false, fmt.Errorf("generate session id: %w", err)
		}
	}
	runID, err := s.newID()
	if err != nil {
		return domain.Run{}, false, fmt.Errorf("generate run id: %w", err)
	}
	run, err := domain.NewRun(runID, cmd.TenantID, cmd.AgentID, cmd.ReleaseID, sessionID, cmd.Input, s.now())
	if err != nil {
		return domain.Run{}, false, err
	}
	return s.repo.CreateRun(ctx, run, cmd.IdempotencyKey, requestHash)
}

func (s *RunService) Get(ctx context.Context, tenantID, runID string) (domain.Run, error) {
	if tenantID == "" || runID == "" {
		return domain.Run{}, fmt.Errorf("%w: tenantId and runId are required", domain.ErrInvalidInput)
	}
	return s.repo.GetRun(ctx, tenantID, runID)
}

func (s *RunService) Transition(ctx context.Context, tenantID, runID string, expectedVersion int64, target domain.RunStatus, reason string) (domain.Run, error) {
	if tenantID == "" || runID == "" || expectedVersion < 1 {
		return domain.Run{}, fmt.Errorf("%w: tenantId, runId and positive expectedVersion are required", domain.ErrInvalidInput)
	}
	return s.repo.TransitionRun(ctx, tenantID, runID, expectedVersion, target, reason, s.now())
}

func hashCreateCommand(cmd CreateRunCommand) (string, error) {
	input := cmd.Input
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", fmt.Errorf("%w: invalid input JSON: %v", domain.ErrInvalidInput, err)
	}
	canonical, err := json.Marshal(struct {
		TenantID  string `json:"tenantId"`
		AgentID   string `json:"agentId"`
		ReleaseID string `json:"releaseId"`
		SessionID string `json:"sessionId,omitempty"`
		Input     any    `json:"input"`
	}{cmd.TenantID, cmd.AgentID, cmd.ReleaseID, cmd.SessionID, value})
	if err != nil {
		return "", fmt.Errorf("canonicalize request: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
