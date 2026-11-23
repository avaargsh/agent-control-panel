// Package issuegoal prepares a GitHub Issue Goal for ACP RunIntent admission.
// It performs no GitHub request, authorization, Runtime dispatch or tool effect.
package issuegoal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

const (
	ManifestVersion   = "acp.issue-goal/v1"
	SubmissionVersion = "acp.issue-goal-submission/v1"
	InputKind         = "github.issue.fix.v1"
)

var (
	ErrInvalidGoal = errors.New("invalid issue goal manifest")
	ownerPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	repoPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
)

type Target struct {
	TenantID  string `json:"tenant_id"`
	ProjectID string `json:"project_id"`
	AgentID   string `json:"agent_id"`
	ReleaseID string `json:"release_id"`
	SessionID string `json:"session_id"`
}

type Budget struct {
	MaxTokens         int64 `json:"max_tokens"`
	MaxRuntimeSeconds int64 `json:"max_runtime_seconds"`
	MaxSandboxSeconds int64 `json:"max_sandbox_seconds"`
}

type Manifest struct {
	SchemaVersion          string `json:"schema_version"`
	Target                 Target `json:"target"`
	IdempotencyKey         string `json:"idempotency_key"`
	IssueURL               string `json:"issue_url"`
	IssueSnapshotDigest    string `json:"issue_snapshot_digest"`
	TargetBranch           string `json:"target_branch"`
	ExperimentBaselineSHA  string `json:"experiment_baseline_sha"`
	IntegrationBaselineSHA string `json:"integration_baseline_sha"`
	AcceptanceRulesDigest  string `json:"acceptance_rules_digest"`
	Budget                 Budget `json:"budget"`
}

// Input is a deterministic JSON object whose EXACT bytes are hashed by the
// existing ACP execution-input algorithm. Its fields are intent only: no
// immutable SHA, rule digest or budget is verified/enforced until admission.
type Input struct {
	Kind                   string `json:"kind"`
	IssueURL               string `json:"issue_url"`
	IssueSnapshotDigest    string `json:"issue_snapshot_digest"`
	TargetBranch           string `json:"target_branch"`
	ExperimentBaselineSHA  string `json:"experiment_baseline_sha"`
	IntegrationBaselineSHA string `json:"integration_baseline_sha"`
	AcceptanceRulesDigest  string `json:"acceptance_rules_digest"`
	Budget                 Budget `json:"budget"`
}

// Prepared is a portable, non-authoritative admission proposal. Base64 avoids
// accidental JSON reformatting that would change the exact-byte digest.
type Prepared struct {
	Schema               string `json:"schema"`
	Target               Target `json:"target"`
	IdempotencyKey       string `json:"idempotency_key"`
	RequestDigest        string `json:"request_digest"`
	ExecutionInputBase64 string `json:"execution_input_base64"`
}

// Prepare validates a strict manifest and computes ACP's execution-input
// digest. It does not accept a RunIntent or check that an Issue/commit exists.
func Prepare(raw []byte) (Prepared, error) {
	if len(raw) == 0 || len(raw) > 32*1024 {
		return Prepared{}, ErrInvalidGoal
	}
	// Reuse the ACP token-walker to reject duplicate JSON keys (including
	// escaped spellings), deep input and trailing content before decoding.
	probe := runintent.Intent{TenantID: "manifest", ProjectID: "manifest", AgentID: "manifest", ReleaseID: "manifest", SessionID: "manifest", IdempotencyKey: "manifest"}
	if _, err := runintent.ExecutionInputDigest(probe, raw); err != nil {
		return Prepared{}, fmt.Errorf("%w: invalid or ambiguous JSON", ErrInvalidGoal)
	}
	if err := ValidateUniqueJSONKeys(raw); err != nil {
		return Prepared{}, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Prepared{}, fmt.Errorf("%w: %v", ErrInvalidGoal, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Prepared{}, ErrInvalidGoal
	}
	if err := m.validate(); err != nil {
		return Prepared{}, err
	}
	input := Input{
		Kind: InputKind, IssueURL: m.IssueURL, IssueSnapshotDigest: m.IssueSnapshotDigest, TargetBranch: m.TargetBranch,
		ExperimentBaselineSHA:  m.ExperimentBaselineSHA,
		IntegrationBaselineSHA: m.IntegrationBaselineSHA,
		AcceptanceRulesDigest:  m.AcceptanceRulesDigest, Budget: m.Budget,
	}
	exact, err := json.Marshal(input)
	if err != nil {
		return Prepared{}, err
	}
	digest, err := runintent.ExecutionInputDigest(runintent.Intent{
		TenantID: m.Target.TenantID, ProjectID: m.Target.ProjectID,
		AgentID: m.Target.AgentID, ReleaseID: m.Target.ReleaseID,
		SessionID: m.Target.SessionID, IdempotencyKey: m.IdempotencyKey,
	}, exact)
	if err != nil {
		return Prepared{}, fmt.Errorf("%w: invalid target scope", ErrInvalidGoal)
	}
	return Prepared{
		Schema: SubmissionVersion, Target: m.Target,
		IdempotencyKey: m.IdempotencyKey, RequestDigest: digest,
		ExecutionInputBase64: base64.StdEncoding.EncodeToString(exact),
	}, nil
}

func (m Manifest) validate() error {
	if m.SchemaVersion != ManifestVersion || m.IdempotencyKey == "" || len(m.IdempotencyKey) > 128 ||
		strings.TrimSpace(m.IdempotencyKey) != m.IdempotencyKey ||
		strings.ContainsAny(m.IdempotencyKey, " \t\r\n\x00") {
		return ErrInvalidGoal
	}
	if !validGitHubIssueURL(m.IssueURL) || !validBranch(m.TargetBranch) ||
		!strings.HasPrefix(m.IssueSnapshotDigest, "sha256:") ||
		!validHex(strings.TrimPrefix(m.IssueSnapshotDigest, "sha256:"), 64) ||
		!validHex(m.ExperimentBaselineSHA, 40) || !validHex(m.IntegrationBaselineSHA, 40) ||
		!strings.HasPrefix(m.AcceptanceRulesDigest, "sha256:") ||
		!validHex(strings.TrimPrefix(m.AcceptanceRulesDigest, "sha256:"), 64) {
		return ErrInvalidGoal
	}
	if m.Budget.MaxTokens <= 0 || m.Budget.MaxTokens > 10_000_000 ||
		m.Budget.MaxRuntimeSeconds <= 0 || m.Budget.MaxRuntimeSeconds > 86_400 ||
		m.Budget.MaxSandboxSeconds <= 0 || m.Budget.MaxSandboxSeconds > m.Budget.MaxRuntimeSeconds {
		return ErrInvalidGoal
	}
	return nil
}

func validGitHubIssueURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" ||
		u.RawPath != "" || strings.Contains(value, "%") {
		return false
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 5 || parts[0] != "" || parts[3] != "issues" ||
		!ownerPattern.MatchString(parts[1]) || strings.HasSuffix(parts[1], "-") ||
		!repoPattern.MatchString(parts[2]) || parts[2] == "." || parts[2] == ".." {
		return false
	}
	n, err := strconv.ParseUint(parts[4], 10, 64)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == parts[4] && u.String() == value
}

func validBranch(branch string) bool {
	if branch == "" || len(branch) > 200 || strings.HasPrefix(branch, "/") ||
		strings.HasSuffix(branch, "/") || strings.HasPrefix(branch, "refs/") ||
		strings.Contains(branch, "..") || strings.ContainsAny(branch, " ~^:?*[\\@\t\r\n") {
		return false
	}
	for _, segment := range strings.Split(branch, "/") {
		if segment == "" || strings.HasPrefix(segment, ".") ||
			strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, ".lock") {
			return false
		}
		for _, ch := range segment {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.') {
				return false
			}
		}
	}
	return true
}

func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}
