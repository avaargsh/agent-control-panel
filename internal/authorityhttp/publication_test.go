package authorityhttp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

func TestPublishExactReleaseContentAndRejectTamper(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	config := ReleaseConfig{
		SchemaVersion: "acp.release-publication.v1", TenantID: "tenant-1", ProjectID: "project-1",
		AgentID: "agent-1", AgentReleaseID: "release-1", PolicyRevision: "policy-1",
		CatalogVersion: "1.0.0", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Services: []string{"payments"},
		Capabilities: []CapabilityContract{{
			ID: "sre.metrics.read", Version: "1.0.0",
			InputSchema:  json.RawMessage(`{"type":"object","required":["service"]}`),
			OutputSchema: json.RawMessage(`{"type":"object","required":["series"]}`),
			EffectClass:  "read_only", Idempotency: "safe", TenantScoped: true,
		}},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	ref := runpg.ExecutionAuthorityRef{TenantID: "tenant-1", RunIntentID: "11111111-1111-4111-8111-111111111111",
		RunID: "22222222-2222-4222-8222-222222222222", RequestDigest: "sha256:" + digest}
	authority := Snapshot{
		SchemaVersion: "acp.run-authority.v1", TenantID: ref.TenantID, RunIntentID: ref.RunIntentID,
		RunID: ref.RunID, RequestDigest: ref.RequestDigest, ProjectID: config.ProjectID,
		AgentID: config.AgentID, AgentReleaseID: config.AgentReleaseID, SessionID: "session-1",
		PrincipalID: "principal-1", SubjectID: "subject-1", ActorID: "subject-1",
		PolicyRevision: config.PolicyRevision, ConfigDigest: "sha256:" + digest,
	}
	dir := t.TempDir()
	file := filepath.Join(dir, digest+".json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPublisher(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	input := []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
	first, err := p.Publish(authority, input, now)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, first.Payload, first.Signature) {
		t.Fatal("published content lacks authentic detached signature")
	}
	var record Publication
	if err := json.Unmarshal(first.Payload, &record); err != nil {
		t.Fatal(err)
	}
	if record.Authority != authority || record.Context.Service != "payments" || len(record.Capabilities) != 1 ||
		record.ContextSnapshot.SHA256 != sha256Hex(record.ContextContent) ||
		record.CapabilitySnapshot.SHA256 != sha256Hex(record.CapabilityContent) ||
		record.Capabilities[0].InputSchemaRef != "sha256:"+sha256Hex(config.Capabilities[0].InputSchema) {
		t.Fatalf("publication does not bind actual release and Run: %+v", record)
	}
	// Guard must not promote a previously published capability to a
	// transferable grant. Only the fresh ACP-owned release, original
	// Run admission and resource service can validate this narrow selector.
	selectStep := GuardCapabilityRequest{
		SchemaVersion: GuardCapabilitySchema, RunID: authority.RunID,
		AgentID: authority.AgentID, AgentReleaseID: authority.AgentReleaseID,
		SessionID: authority.SessionID, CapabilityID: "sre.metrics.read",
		CapabilityVersion: "1.0.0", ResourceRef: "payments",
	}
	verified, err := MatchGuardCapability(record, selectStep)
	if err != nil || verified.Status != "VERIFIED" ||
		verified.ContractSHA256 != record.Capabilities[0].ContractSHA256 ||
		verified.PolicyRevision != authority.PolicyRevision {
		t.Fatalf("fresh authority did not bind exact read-only capability: %+v %v", verified, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Publication, *GuardCapabilityRequest)
	}{
		{"different Run", func(_ *Publication, q *GuardCapabilityRequest) { q.RunID = "33333333-3333-4333-8333-333333333333" }},
		{"different Release", func(_ *Publication, q *GuardCapabilityRequest) { q.AgentReleaseID = "release-attacker" }},
		{"different Session", func(_ *Publication, q *GuardCapabilityRequest) { q.SessionID = "session-attacker" }},
		{"different capability", func(_ *Publication, q *GuardCapabilityRequest) { q.CapabilityID = "workspace.write" }},
		{"wrong version", func(_ *Publication, q *GuardCapabilityRequest) { q.CapabilityVersion = "2.0.0" }},
		{"other resource", func(_ *Publication, q *GuardCapabilityRequest) { q.ResourceRef = "other" }},
		{"effectful capability", func(a *Publication, _ *GuardCapabilityRequest) { a.Capabilities[0].EffectClass = "write" }},
		{"unsafe idempotency", func(a *Publication, _ *GuardCapabilityRequest) { a.Capabilities[0].Idempotency = "unsafe" }},
		// RED regression: all of these used to match despite diverging from
		// the immutable release/config and context bytes that Publisher signed.
		{"forged contract digest", func(a *Publication, _ *GuardCapabilityRequest) {
			a.Capabilities[0].ContractSHA256 = sha256Hex([]byte("forged-contract"))
		}},
		{"forged input schema digest", func(a *Publication, _ *GuardCapabilityRequest) {
			a.Capabilities[0].InputSchemaRef = "sha256:" + sha256Hex([]byte("forged-input"))
		}},
		{"forged output schema digest", func(a *Publication, _ *GuardCapabilityRequest) {
			a.Capabilities[0].OutputSchemaRef = "sha256:" + sha256Hex([]byte("forged-output"))
		}},
		{"forged context field", func(a *Publication, q *GuardCapabilityRequest) {
			a.Context.Service = "other"
			q.ResourceRef = "other"
		}},
		{"forged config digest", func(a *Publication, _ *GuardCapabilityRequest) {
			a.Authority.ConfigDigest = "sha256:" + sha256Hex([]byte("forged-config"))
			a.Context.Authority = a.Authority
		}},

	} {
		t.Run("Guard rejects "+tc.name, func(t *testing.T) {
			a := record
			a.Capabilities = append([]CapabilityRef{}, record.Capabilities...)
			q := selectStep
			tc.change(&a, &q)
			if _, err := MatchGuardCapability(a, q); err == nil {
				t.Fatal("untrusted capability selector granted by ACP")
			}
		})
	}
	if bytes.Contains(first.Payload, []byte("execution_input")) || bytes.Contains(first.Payload, []byte("access_token")) {
		t.Fatal("publication exposed raw input or credential")
	}
	again, err := p.Publish(authority, input, now.Add(time.Second))
	if err != nil || !bytes.Equal(first.Payload, again.Payload) || !bytes.Equal(first.Signature, again.Signature) {
		t.Fatal("same accepted Run did not produce identical signed publication")
	}
	bad := []byte(`{"objective":"sre_incident_triage","service":"other","signal":"latency"}`)
	if _, err := p.Publish(authority, bad, now); !errors.Is(err, ErrPublicationDenied) {
		t.Fatalf("foreign service acquired capability publication: %v", err)
	}
	if _, err := p.Publish(authority, input, config.ExpiresAt); !errors.Is(err, ErrPublicationDenied) {
		t.Fatalf("expired release was published: %v", err)
	}
	if err := os.WriteFile(file, append(raw, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publish(authority, input, now); !errors.Is(err, ErrPublicationUnavailable) {
		t.Fatalf("mutated content accepted under original digest: %v", err)
	}
}
