package authorityhttp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func protectedFixture(t *testing.T, now time.Time) (Snapshot, []byte, []byte, GuardProtectedWorkspaceRequest) {
	t.Helper()
	release := ProtectedWorkspaceRelease{
		SchemaVersion: "acp.protected-workspace-release.v1",
		TenantID: "tenant-1", ProjectID: "project-1",
		AgentID: "agent-1", AgentReleaseID: "release-1",
		PolicyRevision: "policy-1", IssuedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(5 * time.Minute),
		Capability: ProtectedWorkspaceContract{
			ID: "workspace.write", Version: "1.0.0",
			EffectClass: "protected_write", Idempotency: "guard_permit_once",
			TenantScoped: true, ApprovalRequired: true,
			ToolBindingDigest: strings.Repeat("a", 64),
			Audience: "trusted-workspace-executor", WorkspaceID: "workspace-1",
		},
	}
	raw, err := json.Marshal(release)
	if err != nil { t.Fatal(err) }
	a := Snapshot{
		SchemaVersion: "acp.run-authority.v1", TenantID: "tenant-1",
		RunIntentID: "11111111-1111-4111-8111-111111111111",
		RunID: "22222222-2222-4222-8222-222222222222",
		RequestDigest: "sha256:" + strings.Repeat("b",64),
		ProjectID: "project-1", AgentID: "agent-1",
		AgentReleaseID: "release-1", SessionID: "session-1",
		PrincipalID: "principal-1", SubjectID: "subject-1",
		ActorID: "subject-1", PolicyRevision: "policy-1",
		ConfigDigest: "sha256:" + sha256Hex(raw),
	}
	input := []byte(`{"objective":"workspace_write","workspace_id":"workspace-1"}`)
	req := GuardProtectedWorkspaceRequest{
		SchemaVersion: GuardProtectedWorkspaceSchema, RunID: a.RunID,
		AgentID: a.AgentID, AgentReleaseID: a.AgentReleaseID, SessionID: a.SessionID,
		SubjectID: a.SubjectID, CapabilityID: "workspace.write", CapabilityVersion: "1.0.0",
		PolicyRevision: a.PolicyRevision, WorkspaceID: "workspace-1",
		ToolBindingDigest: strings.Repeat("a",64), Audience: "trusted-workspace-executor",
	}
	return a, input, raw, req
}

func TestProtectedWorkspaceAuthorityRequiresExactLiveRunIntentAndImmutableRelease(t *testing.T) {
	now := time.Date(2026, 11, 18, 11, 0, 0, 0, time.UTC)
	a, input, release, req := protectedFixture(t, now)
	got, err := VerifyProtectedWorkspaceRelease(a, input, release, req, now)
	if err != nil || got.Status != "VERIFIED" || got.RunID != a.RunID ||
		got.ConfigDigest != a.ConfigDigest || got.WorkspaceID != req.WorkspaceID ||
		got.ToolBindingDigest != req.ToolBindingDigest || got.PolicyRevision != req.PolicyRevision ||
		got.Audience != req.Audience || len(got.ContractSHA256) != 64 {
		t.Fatalf("protected release rejected or unbound: %+v %v", got, err)
	}
	for _, tc := range []struct {
		name string
		change func(*Snapshot, *[]byte, *[]byte, *GuardProtectedWorkspaceRequest)
	}{
		{"wrong tenant", func(a *Snapshot, _ *[]byte, _ *[]byte, _ *GuardProtectedWorkspaceRequest) { a.TenantID = "tenant-2" }},
		{"wrong project", func(a *Snapshot, _ *[]byte, _ *[]byte, _ *GuardProtectedWorkspaceRequest) { a.ProjectID = "project-2" }},
		{"wrong actor", func(a *Snapshot, _ *[]byte, _ *[]byte, _ *GuardProtectedWorkspaceRequest) { a.ActorID = "other" }},
		{"missing principal", func(a *Snapshot, _ *[]byte, _ *[]byte, _ *GuardProtectedWorkspaceRequest) { a.PrincipalID = "" }},
		{"other Run", func(_ *Snapshot, _ *[]byte, _ *[]byte, q *GuardProtectedWorkspaceRequest) { q.RunID = "33333333-3333-4333-8333-333333333333" }},
		{"other release", func(_ *Snapshot, _ *[]byte, _ *[]byte, q *GuardProtectedWorkspaceRequest) { q.AgentReleaseID = "release-2" }},
		{"other session", func(_ *Snapshot, _ *[]byte, _ *[]byte, q *GuardProtectedWorkspaceRequest) { q.SessionID = "session-2" }},
		{"other subject", func(_ *Snapshot, _ *[]byte, _ *[]byte, q *GuardProtectedWorkspaceRequest) { q.SubjectID = "subject-2" }},
		{"other policy", func(_ *Snapshot, _ *[]byte, _ *[]byte, q *GuardProtectedWorkspaceRequest) { q.PolicyRevision = "policy-2" }},
		{"other workspace", func(_ *Snapshot, _ *[]byte, _ *[]byte, q *GuardProtectedWorkspaceRequest) { q.WorkspaceID = "workspace-2" }},
		{"other binding", func(_ *Snapshot, _ *[]byte, _ *[]byte, q *GuardProtectedWorkspaceRequest) { q.ToolBindingDigest = strings.Repeat("c",64) }},
		{"other audience", func(_ *Snapshot, _ *[]byte, _ *[]byte, q *GuardProtectedWorkspaceRequest) { q.Audience = "other-executor" }},
		{"other capability", func(_ *Snapshot, _ *[]byte, _ *[]byte, q *GuardProtectedWorkspaceRequest) { q.CapabilityID = "sre.metrics.read" }},
		{"other version", func(_ *Snapshot, _ *[]byte, _ *[]byte, q *GuardProtectedWorkspaceRequest) { q.CapabilityVersion = "2.0.0" }},
		{"foreign immutable digest", func(a *Snapshot, _ *[]byte, _ *[]byte, _ *GuardProtectedWorkspaceRequest) { a.ConfigDigest = "sha256:" + strings.Repeat("c",64) }},
		{"changed content", func(_ *Snapshot, _ *[]byte, raw *[]byte, _ *GuardProtectedWorkspaceRequest) { *raw = append(*raw,' ') }},
		{"read only input", func(_ *Snapshot, in *[]byte, _ *[]byte, _ *GuardProtectedWorkspaceRequest) { *in = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`) }},
		{"other original intent", func(_ *Snapshot, in *[]byte, _ *[]byte, _ *GuardProtectedWorkspaceRequest) { *in = []byte(`{"objective":"workspace_write","workspace_id":"workspace-2"}`) }},
		{"missing original input", func(_ *Snapshot, in *[]byte, _ *[]byte, _ *GuardProtectedWorkspaceRequest) { *in = nil }},
	} {
		t.Run(tc.name,func(t *testing.T){
			current := a
			currentInput := append([]byte{},input...)
			currentRelease := append([]byte{},release...)
			currentReq := req
			tc.change(&current,&currentInput,&currentRelease,&currentReq)
			if _, err := VerifyProtectedWorkspaceRelease(current,currentInput,currentRelease,currentReq,now); !errors.Is(err,ErrProtectedWorkspaceDenied) {
				t.Fatalf("protected write preflight accepted %s: %v",tc.name,err)
			}
		})
	}
}

func TestProtectedWorkspaceReleaseRejectsForgedEffectScopeAndExpiry(t *testing.T) {
	now:=time.Date(2026,11,18,11,0,0,0,time.UTC)
	a,input,raw,q:=protectedFixture(t,now)
	for _, tc:=range []struct{
		name string
		change func(*ProtectedWorkspaceRelease)
	}{
		{"read only",func(r *ProtectedWorkspaceRelease){r.Capability.EffectClass="read_only"}},
		{"unsafe idempotency",func(r *ProtectedWorkspaceRelease){r.Capability.Idempotency="unsafe"}},
		{"no approval",func(r *ProtectedWorkspaceRelease){r.Capability.ApprovalRequired=false}},
		{"unscoped",func(r *ProtectedWorkspaceRelease){r.Capability.TenantScoped=false}},
		{"wildcard workspace",func(r *ProtectedWorkspaceRelease){r.Capability.WorkspaceID="*"}},
		{"other audience",func(r *ProtectedWorkspaceRelease){r.Capability.Audience="some-other-executor"}},
		{"other binding",func(r *ProtectedWorkspaceRelease){r.Capability.ToolBindingDigest=strings.Repeat("c",64)}},
		{"wrong policy",func(r *ProtectedWorkspaceRelease){r.PolicyRevision="policy-0"}},
		{"wrong agent",func(r *ProtectedWorkspaceRelease){r.AgentID="agent-2"}},
		{"wrong schema",func(r *ProtectedWorkspaceRelease){r.SchemaVersion="acp.release-publication.v1"}},
		{"expired",func(r *ProtectedWorkspaceRelease){r.ExpiresAt=now}},
		{"not yet active",func(r *ProtectedWorkspaceRelease){r.IssuedAt=now.Add(time.Minute)}},
		{"excessive TTL",func(r *ProtectedWorkspaceRelease){r.ExpiresAt=r.IssuedAt.Add(24*time.Hour)}},
	} {
		t.Run(tc.name,func(t *testing.T){
			var release ProtectedWorkspaceRelease
			if err:=json.Unmarshal(raw,&release);err!=nil {t.Fatal(err)}
			tc.change(&release)
			changed,err:=json.Marshal(release)
			if err!=nil {t.Fatal(err)}
			current:=a
			current.ConfigDigest="sha256:"+sha256Hex(changed)
			if _,err:=VerifyProtectedWorkspaceRelease(current,input,changed,q,now);!errors.Is(err,ErrProtectedWorkspaceDenied){
				t.Fatalf("matching digest made invalid protected release valid: %v",err)
			}
		})
	}
	for _, malformed:=range [][]byte{
		[]byte(`{"schema_version":"acp.protected-workspace-release.v1","schema_version":"x"}`),
		[]byte(`{"unknown":"unsafe"}`),
		append(append([]byte{},raw...),' '),
	} {
		current:=a
		current.ConfigDigest="sha256:"+sha256Hex(malformed)
		if _,err:=VerifyProtectedWorkspaceRelease(current,input,malformed,q,now);!errors.Is(err,ErrProtectedWorkspaceDenied){
			t.Fatalf("malformed content accepted with matching hash: %v",err)
		}
	}
}

func TestExistingReadOnlyReleaseNeverBecomesProtectedWrite(t *testing.T) {
	now:=time.Date(2026,11,18,11,0,0,0,time.UTC)
	a,input,_,q:=protectedFixture(t,now)
	legacy:=ReleaseConfig{
		SchemaVersion:"acp.release-publication.v1",TenantID:a.TenantID,
		ProjectID:a.ProjectID,AgentID:a.AgentID,AgentReleaseID:a.AgentReleaseID,
		PolicyRevision:a.PolicyRevision,CatalogVersion:"1.0.0",
		IssuedAt:now.Add(-time.Minute),ExpiresAt:now.Add(time.Hour),
		Services:[]string{"workspace-1"},Capabilities:[]CapabilityContract{{
			ID:"sre.metrics.read",Version:"1.0.0",InputSchema:json.RawMessage(`{"type":"object"}`),
			OutputSchema:json.RawMessage(`{"type":"object"}`),EffectClass:"read_only",
			Idempotency:"safe",TenantScoped:true,
		}},
	}
	raw,err:=json.Marshal(legacy)
	if err!=nil {t.Fatal(err)}
	a.ConfigDigest="sha256:"+sha256Hex(raw)
	if _,err:=VerifyProtectedWorkspaceRelease(a,input,raw,q,now);!errors.Is(err,ErrProtectedWorkspaceDenied){
		t.Fatalf("legacy read-only publication promoted to workspace write: %v",err)
	}
}
