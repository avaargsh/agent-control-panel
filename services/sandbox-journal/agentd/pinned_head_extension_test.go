package agentd

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPinnedHeadExtensionRequiresOriginalAcceptedPrefix(t *testing.T) {
	authorityKey, authoritySigner := testSourceInspectKey(t)
	sourceKey, sourceSigner := testSourceInspectKey(t)
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	ref := Ref{
		TenantID: "tenant-1", RunID: "run-1", RuntimeAttemptID: "runtime-1",
		SandboxUID: "sandbox-1", CommandID: "command-1", AttemptID: "attempt-1",
		ProviderCommandUID: "provider-1", RequestDigest: "sha256:" + strings.Repeat("a", 64),
		GuardPermitID: "permit-1", PermitEpoch: 1,
		ProcessPID: 123, ProcessStartTicks: 456,
		HostBootID: "11111111-1111-4111-8111-111111111111",
	}
	chain := func(start time.Time, signer ed25519.PrivateKey) []JournaledInspection {
		t.Helper()
		var rows []JournaledInspection
		previous := ""
		for i := uint64(1); i <= 3; i++ {
			event := InspectEvent{
				Schema: InspectSchema, Source: "agentd.inspect", Ref: ref,
				ObservedAt:   start.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano),
				InspectCount: i, JournalVersion: i, PreviousDigest: previous,
				State: Unknown, NextAction: Hold, DispatchCount: 1,
			}
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			previous = digest(raw)
			rows = append(rows, JournaledInspection{Event: event, Payload: raw,
				Signature: ed25519.Sign(signer, append([]byte(InspectDomain), raw...)), Digest: previous})
		}
		return rows
	}
	head := func(row JournaledInspection) InspectHead {
		return InspectHead{InspectCount: row.Event.InspectCount, JournalVersion: row.Event.JournalVersion, Digest: row.Digest}
	}
	original := chain(now.Add(-time.Minute), sourceSigner)
	floor := head(original[1])
	grant := func(h InspectHead, signer ed25519.PrivateKey) ([]byte, []byte) {
		t.Helper()
		raw, err := json.Marshal(headGrantWireFixture{
			Schema: "acp.agentd-pinned-head-grant/v1", Ref: ref, Head: h,
			IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw, ed25519.Sign(signer, append([]byte("acp.agentd-pinned-head-grant/v1\x00"), raw...))
	}
	fork := chain(now.Add(-2*time.Minute), sourceSigner)
	if err := VerifyInspectAtHead(fork, ref, sourceKey, now, head(fork[2])); err != nil {
		t.Fatalf("fork fixture is not a valid signed chain: %v", err)
	}
	for _, tc := range []struct {
		name      string
		rows      []JournaledInspection
		candidate InspectHead
		source    ed25519.PublicKey
		want      bool
	}{
		{"valid extension", original, head(original[2]), sourceKey, true},
		{"same accepted head", original[:2], floor, sourceKey, true},
		{"valid signed fork", fork, head(fork[2]), sourceKey, false},
		{"truncated candidate", original[:2], head(original[2]), sourceKey, false},
		{"empty chain", nil, head(original[2]), sourceKey, false},
		{"rollback", original[:1], head(original[0]), sourceKey, false},
		{"wrong source key", original, head(original[2]), authorityKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, sig := grant(tc.candidate, authoritySigner)
			got, err := VerifyPinnedHeadExtension(raw, sig, tc.rows, ref, floor, authorityKey, tc.source, now)
			if tc.want {
				if err != nil || got != tc.candidate {
					t.Fatalf("valid extension rejected: %+v %v", got, err)
				}
			} else if err == nil || got != (InspectHead{}) {
				t.Fatalf("unverified extension accepted: %+v %v", got, err)
			}
		})
	}
	// Even a fully valid chain and grant must use separately configured keys.
	shared := chain(now.Add(-time.Minute), authoritySigner)
	raw, sig := grant(head(shared[2]), authoritySigner)
	if got, err := VerifyPinnedHeadExtension(raw, sig, shared, ref, head(shared[1]), authorityKey, authorityKey, now); err == nil || got != (InspectHead{}) {
		t.Fatalf("shared authority and source key accepted: %+v %v", got, err)
	}
}
