package agentd

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Wire fixture deliberately uses a separate type, so the test pins the
// public contract rather than relying on the implementation's serializer.
type headGrantWireFixture struct {
	Schema    string      `json:"schema"`
	Ref       Ref         `json:"ref"`
	Head      InspectHead `json:"head"`
	IssuedAt  string      `json:"issued_at"`
	ExpiresAt string      `json:"expires_at"`
}

func TestPinnedHeadGrantRequiresIndependentSignatureScopeFreshnessAndFloor(t *testing.T) {
	key, signer := testSourceInspectKey(t)
	otherKey, otherSigner := testSourceInspectKey(t)
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	ref := Ref{
		TenantID: "tenant-1", RunID: "run-1", RuntimeAttemptID: "runtime-1",
		SandboxUID: "sandbox-1", CommandID: "command-1", AttemptID: "attempt-1",
		ProviderCommandUID: "provider-1", RequestDigest: "sha256:" + strings.Repeat("a", 64),
		GuardPermitID: "permit-1", PermitEpoch: 1,
		ProcessPID: 123, ProcessStartTicks: 456,
		HostBootID: "11111111-1111-4111-8111-111111111111",
	}
	floor := InspectHead{InspectCount: 2, JournalVersion: 2, Digest: "sha256:" + strings.Repeat("b", 64)}
	head := InspectHead{InspectCount: 3, JournalVersion: 3, Digest: "sha256:" + strings.Repeat("c", 64)}
	grant := headGrantWireFixture{
		Schema: "acp.agentd-pinned-head-grant/v1", Ref: ref, Head: head,
		IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	mint := func(g headGrantWireFixture, private ed25519.PrivateKey) ([]byte, []byte) {
		t.Helper()
		raw, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		return raw, ed25519.Sign(private, append([]byte("acp.agentd-pinned-head-grant/v1\x00"), raw...))
	}
	raw, sig := mint(grant, signer)
	got, err := VerifyPinnedHeadGrant(raw, sig, ref, floor, key, now)
	if err != nil || got != head {
		t.Fatalf("valid independently signed fresh head rejected: %+v %v", got, err)
	}
	same := grant
	same.Head = floor
	raw, sig = mint(same, signer)
	if got, err := VerifyPinnedHeadGrant(raw, sig, ref, floor, key, now); err != nil || got != floor {
		t.Fatalf("same independently accepted head rejected: %+v %v", got, err)
	}
	for _, tc := range []struct {
		name string
		edit func(*headGrantWireFixture)
	}{
		{"wrong tenant", func(g *headGrantWireFixture) { g.Ref.TenantID = "tenant-2" }},
		{"wrong run", func(g *headGrantWireFixture) { g.Ref.RunID = "run-2" }},
		{"wrong attempt", func(g *headGrantWireFixture) { g.Ref.AttemptID = "attempt-2" }},
		{"wrong permit epoch", func(g *headGrantWireFixture) { g.Ref.PermitEpoch++ }},
		{"expired", func(g *headGrantWireFixture) { g.ExpiresAt = now.Format(time.RFC3339Nano) }},
		{"future issued", func(g *headGrantWireFixture) { g.IssuedAt = now.Add(time.Second).Format(time.RFC3339Nano) }},
		{"excessive lifetime", func(g *headGrantWireFixture) { g.ExpiresAt = now.Add(6 * time.Minute).Format(time.RFC3339Nano) }},
		{"wrong schema", func(g *headGrantWireFixture) { g.Schema = "other" }},
		{"rollback", func(g *headGrantWireFixture) {
			g.Head = InspectHead{InspectCount: 1, JournalVersion: 1, Digest: floor.Digest}
		}},
		{"equivocation", func(g *headGrantWireFixture) {
			g.Head.InspectCount, g.Head.JournalVersion = floor.InspectCount, floor.JournalVersion
		}},
		{"mismatched revision", func(g *headGrantWireFixture) { g.Head.JournalVersion++ }},
		{"malformed digest", func(g *headGrantWireFixture) { g.Head.Digest = "sha256:" + strings.Repeat("z", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := grant
			tc.edit(&mutated)
			raw, sig := mint(mutated, signer)
			if got, err := VerifyPinnedHeadGrant(raw, sig, ref, floor, key, now); err == nil || got != (InspectHead{}) {
				t.Fatalf("invalid head grant returned authority: %+v %v", got, err)
			}
		})
	}
	raw, sig = mint(grant, signer)
	if _, err := VerifyPinnedHeadGrant(raw, sig, ref, floor, otherKey, now); err == nil {
		t.Fatal("untrusted authority key accepted")
	}
	raw, sig = mint(grant, otherSigner)
	if _, err := VerifyPinnedHeadGrant(raw, sig, ref, floor, key, now); err == nil {
		t.Fatal("untrusted signer accepted")
	}
	raw, sig = mint(grant, signer)
	if _, err := VerifyPinnedHeadGrant(raw, sig, ref, InspectHead{}, key, now); err == nil {
		t.Fatal("missing independent baseline accepted")
	}
	raw = append(raw, ' ')
	sig = ed25519.Sign(signer, append([]byte("acp.agentd-pinned-head-grant/v1\x00"), raw...))
	if _, err := VerifyPinnedHeadGrant(raw, sig, ref, floor, key, now); err == nil {
		t.Fatal("noncanonical signed grant accepted")
	}
}
