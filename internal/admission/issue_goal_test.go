package admission

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

const issueGoalManifest = `{"schema_version":"acp.issue-goal/v1","target":{"tenant_id":"tenant-a","project_id":"project-a","agent_id":"agent-a","release_id":"release-a","session_id":"session-a"},"idempotency_key":"issue-123","issue_url":"https://github.com/example/repository/issues/123","issue_snapshot_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","target_branch":"main","experiment_baseline_sha":"1111111111111111111111111111111111111111","integration_baseline_sha":"2222222222222222222222222222222222222222","acceptance_rules_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","budget":{"max_tokens":2048,"max_runtime_seconds":3600,"max_sandbox_seconds":1800}}`

type sourceVerifierFunc func(context.Context, Target, issuegoal.Input) error

func (f sourceVerifierFunc) VerifyIssueGoal(ctx context.Context, target Target, input issuegoal.Input) error {
	return f(ctx, target, input)
}

func preparedGoalWire(t *testing.T) []byte {
	t.Helper()
	proposal, err := issuegoal.Prepare([]byte(issueGoalManifest))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestAdmitPreparedIssueGoalUsesTrustedChecksAndImmutableInput(t *testing.T) {
	wire := preparedGoalWire(t)
	store := &inputCaptureStore{}
	var checked int
	resolver := resolverFunc(func(_ context.Context, req Request) (Grant, error) {
		if req.Target != (Target{TenantID: "tenant-a", ProjectID: "project-a", AgentID: "agent-a", ReleaseID: "release-a", SessionID: "session-a"}) ||
			req.IdempotencyKey != "issue-123" || req.RequestDigest == "" {
			t.Fatalf("incorrect admission selectors: %+v", req)
		}
		_, grant := fixture()
		grant.Target = req.Target
		grant.RequestDigest = req.RequestDigest
		return grant, nil
	})
	svc := New(store, resolver)
	sources := sourceVerifierFunc(func(_ context.Context, target Target, input issuegoal.Input) error {
		checked++
		if target.TenantID != "tenant-a" || input.Kind != issuegoal.InputKind ||
			input.IssueSnapshotDigest != "sha256:"+strings.Repeat("4", 64) ||
			input.AcceptanceRulesDigest != "sha256:"+strings.Repeat("3", 64) ||
			input.Budget.MaxSandboxSeconds != 1800 {
			t.Fatalf("unverified source binding: %+v %+v", target, input)
		}
		return nil
	})
	intent, created, err := svc.AdmitPreparedIssueGoal(context.Background(), wire, sources)
	if err != nil || !created || checked != 1 || store.calls != 1 || intent.Status != runintent.Pending ||
		intent.RunID != "" || intent.WorkflowID != "" {
		t.Fatalf("incorrect intent result: created=%v checked=%d writes=%d err=%v intent=%+v", created, checked, store.calls, err, intent)
	}
	if err := runintent.VerifyExecutionInput(intent, store.raw); err != nil {
		t.Fatalf("stored bytes not bound to intent: %v", err)
	}
}

func TestAdmitPreparedIssueGoalFailsClosedBeforeWriting(t *testing.T) {
	wire := preparedGoalWire(t)
	denied := errors.New("github source unavailable")
	for _, tc := range []struct {
		name          string
		wire          []byte
		verify        sourceVerifierFunc
		resolverError error
	}{
		{name: "no source verifier", wire: wire},
		{name: "source unavailable", wire: wire, verify: sourceVerifierFunc(func(context.Context, Target, issuegoal.Input) error { return denied })},
		{name: "source verified but identity revoked", wire: wire, verify: sourceVerifierFunc(func(context.Context, Target, issuegoal.Input) error { return nil }), resolverError: ErrPolicyDenied},
		{name: "tampered digest", wire: []byte(strings.Replace(string(wire), "sha256:", "sha256:dead", 1)), verify: sourceVerifierFunc(func(context.Context, Target, issuegoal.Input) error {
			t.Fatal("tampered source reached verifier")
			return nil
		})},
		{name: "extra field", wire: []byte(strings.Replace(string(wire), `"schema":`, `"bypass":true,"schema":`, 1)), verify: sourceVerifierFunc(func(context.Context, Target, issuegoal.Input) error {
			t.Fatal("malformed source reached verifier")
			return nil
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &inputCaptureStore{}
			var resolverCalled bool
			svc := New(store, resolverFunc(func(_ context.Context, req Request) (Grant, error) {
				resolverCalled = true
				if tc.resolverError != nil {
					return Grant{}, tc.resolverError
				}
				t.Fatal("unverified proposal reached resolver")
				return Grant{}, nil
			}))
			_, created, err := svc.AdmitPreparedIssueGoal(context.Background(), tc.wire, tc.verify)
			if err == nil || created || store.calls != 0 {
				t.Fatalf("untrusted proposal wrote state: created=%v writes=%d err=%v", created, store.calls, err)
			}
			if tc.name == "source verified but identity revoked" && !resolverCalled {
				t.Fatal("expected live resolver denial")
			}
			if tc.name == "source unavailable" && !errors.Is(err, ErrIssueGoalSourceUnverified) {
				t.Fatalf("source error incorrectly classified: %v", err)
			}
		})
	}
}


func TestAdmitPreparedIssueGoalRejectsTypedNilDependencies(t *testing.T) {
	wire := preparedGoalWire(t)
	var nilSource sourceVerifierFunc
	var nilStore *inputCaptureStore
	var nilResolver resolverFunc
	validSource := sourceVerifierFunc(func(context.Context, Target, issuegoal.Input) error { return nil })
	cases := []struct {
		name string
		service *Service
		source IssueGoalSourceVerifier
	}{
		{name: "typed nil source function", service: New(&inputCaptureStore{}, resolverFunc(func(context.Context, Request) (Grant, error) {
			t.Fatal("nil source reached resolver")
			return Grant{}, nil
		})), source: nilSource},
		{name: "typed nil store pointer", service: New(nilStore, resolverFunc(func(context.Context, Request) (Grant, error) {
			t.Fatal("nil store reached resolver")
			return Grant{}, nil
		})), source: validSource},
		{name: "typed nil resolver function", service: New(&inputCaptureStore{}, nilResolver), source: validSource},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, created, err := tc.service.AdmitPreparedIssueGoal(context.Background(), wire, tc.source)
			if created || !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("typed nil dependency was not rejected: created=%v err=%v", created, err)
			}
		})
	}
}
