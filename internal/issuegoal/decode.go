package issuegoal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

// MaxPreparedBytes bounds the untrusted wire envelope containing a base64
// encoded execution input. This is a proposal, not authentication evidence.
const MaxPreparedBytes = 64 * 1024

// DecodePrepared validates a caller-supplied offline proposal at the ACP
// boundary. A matching client digest is still NOT authorization, source
// existence, a valid policy, or permission to execute.
func DecodePrepared(wire []byte) (Prepared, Input, []byte, error) {
	if len(wire) == 0 || len(wire) > MaxPreparedBytes {
		return Prepared{}, Input{}, nil, ErrInvalidGoal
	}
	probe := runintent.Intent{TenantID: "proposal", ProjectID: "proposal", AgentID: "proposal", ReleaseID: "proposal", SessionID: "proposal", IdempotencyKey: "proposal"}
	if _, err := runintent.ExecutionInputDigest(probe, wire); err != nil {
		return Prepared{}, Input{}, nil, fmt.Errorf("%w: ambiguous proposal JSON", ErrInvalidGoal)
	}
	var p Prepared
	dec := json.NewDecoder(bytes.NewReader(wire))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Prepared{}, Input{}, nil, fmt.Errorf("%w: %v", ErrInvalidGoal, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Prepared{}, Input{}, nil, ErrInvalidGoal
	}
	if p.Schema != SubmissionVersion || len(p.ExecutionInputBase64) == 0 || len(p.ExecutionInputBase64) > ((32*1024+2)/3)*4 {
		return Prepared{}, Input{}, nil, ErrInvalidGoal
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(p.ExecutionInputBase64)
	if err != nil || len(raw) > 32*1024 {
		return Prepared{}, Input{}, nil, ErrInvalidGoal
	}
	if _, err := runintent.ExecutionInputDigest(probe, raw); err != nil {
		return Prepared{}, Input{}, nil, fmt.Errorf("%w: ambiguous execution input", ErrInvalidGoal)
	}
	var input Input
	inputDecoder := json.NewDecoder(bytes.NewReader(raw))
	inputDecoder.DisallowUnknownFields()
	if err := inputDecoder.Decode(&input); err != nil {
		return Prepared{}, Input{}, nil, fmt.Errorf("%w: invalid execution input", ErrInvalidGoal)
	}
	if _, err := inputDecoder.Token(); err != io.EOF {
		return Prepared{}, Input{}, nil, ErrInvalidGoal
	}
	m := Manifest{SchemaVersion: ManifestVersion, Target: p.Target, IdempotencyKey: p.IdempotencyKey, IssueURL: input.IssueURL, TargetBranch: input.TargetBranch, ExperimentBaselineSHA: input.ExperimentBaselineSHA, IntegrationBaselineSHA: input.IntegrationBaselineSHA, AcceptanceRulesDigest: input.AcceptanceRulesDigest, Budget: input.Budget}
	if input.Kind != InputKind || m.validate() != nil {
		return Prepared{}, Input{}, nil, ErrInvalidGoal
	}
	canonical, err := json.Marshal(input)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Prepared{}, Input{}, nil, ErrInvalidGoal
	}
	digest, err := runintent.ExecutionInputDigest(runintent.Intent{TenantID: p.Target.TenantID, ProjectID: p.Target.ProjectID, AgentID: p.Target.AgentID, ReleaseID: p.Target.ReleaseID, SessionID: p.Target.SessionID, IdempotencyKey: p.IdempotencyKey}, raw)
	if err != nil || digest != p.RequestDigest {
		return Prepared{}, Input{}, nil, ErrInvalidGoal
	}
	return p, input, raw, nil
}
