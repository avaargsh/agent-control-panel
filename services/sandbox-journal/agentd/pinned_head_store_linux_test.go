//go:build linux

package agentd

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPinnedHeadStoreDurableCAS(t *testing.T) {
	authorityKey, authoritySigner := testSourceInspectKey(t)
	sourceKey, sourceSigner := testSourceInspectKey(t)
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	ref := Ref{TenantID: "tenant-1", RunID: "run-1", RuntimeAttemptID: "runtime-1", SandboxUID: "sandbox-1", CommandID: "command-1", AttemptID: "attempt-1", ProviderCommandUID: "provider-1", RequestDigest: "sha256:" + strings.Repeat("a", 64), GuardPermitID: "permit-1", PermitEpoch: 1, ProcessPID: 123, ProcessStartTicks: 456, HostBootID: "11111111-1111-4111-8111-111111111111"}
	var events []JournaledInspection
	previous := ""
	for i := uint64(1); i <= 3; i++ {
		event := InspectEvent{Schema: InspectSchema, Source: "agentd.inspect", Ref: ref, ObservedAt: now.Add(-time.Minute + time.Duration(i)*time.Second).Format(time.RFC3339Nano), InspectCount: i, JournalVersion: i, PreviousDigest: previous, State: Unknown, NextAction: Hold, DispatchCount: 1}
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		previous = digest(raw)
		events = append(events, JournaledInspection{Event: event, Payload: raw, Signature: ed25519.Sign(sourceSigner, append([]byte(InspectDomain), raw...)), Digest: previous})
	}
	head := func(i int) InspectHead {
		row := events[i-1]
		return InspectHead{InspectCount: row.Event.InspectCount, JournalVersion: row.Event.JournalVersion, Digest: row.Digest}
	}
	mint := func(h InspectHead) ([]byte, []byte) {
		t.Helper()
		raw, err := json.Marshal(headGrantWireFixture{Schema: "acp.agentd-pinned-head-grant/v1", Ref: ref, Head: h, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)})
		if err != nil {
			t.Fatal(err)
		}
		return raw, ed25519.Sign(authoritySigner, append([]byte("acp.agentd-pinned-head-grant/v1\x00"), raw...))
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	first, err := OpenPinnedHeadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Read(ref); err == nil {
		t.Fatal("missing floor accepted")
	}
	if err := first.Enroll(ref, head(1)); err != nil {
		t.Fatal(err)
	}
	if err := first.Enroll(ref, head(2)); err == nil {
		t.Fatal("enrollment replaced existing floor")
	}
	second, err := OpenPinnedHeadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	raw, sig := mint(head(2))
	raw3, sig3 := mint(head(3))
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for i, store := range []*PinnedHeadStore{first, second} {
		wg.Add(1)
		go func(i int, store *PinnedHeadStore) {
			defer wg.Done()
			if i == 0 {
				_, err := store.Advance(ref, head(1), raw, sig, events[:2], authorityKey, sourceKey, now)
				outcomes <- err
			} else {
				_, err := store.Advance(ref, head(1), raw3, sig3, events, authorityKey, sourceKey, now)
				outcomes <- err
			}
		}(i, store)
	}
	wg.Wait()
	close(outcomes)
	success := 0
	for err := range outcomes {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("CAS accepted %d competing updates", success)
	}
	current, err := second.Read(ref)
	if err != nil {
		t.Fatal(err)
	}
	if current == head(2) {
		if _, err := first.Advance(ref, current, raw3, sig3, events, authorityKey, sourceKey, now); err != nil {
			t.Fatal(err)
		}
	} else if current != head(3) {
		t.Fatalf("unexpected persisted floor: %+v", current)
	}
	if _, err := first.Advance(ref, head(3), raw, sig, events[:2], authorityKey, sourceKey, now); err == nil {
		t.Fatal("rollback accepted")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPinnedHeadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, err := reopened.Read(ref); err != nil || got != head(3) {
		t.Fatalf("reopened store lost floor: %+v %v", got, err)
	}
	foreign := ref
	foreign.RunID = "foreign-run"
	if _, err := reopened.Read(foreign); err == nil {
		t.Fatal("foreign run read same floor")
	}
}

func TestPinnedHeadStoreRejectsUntrustedDirectoryAndSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenPinnedHeadStore(dir); err == nil {
		s.Close()
		t.Fatal("world writable store accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	link := t.TempDir() + "/link"
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenPinnedHeadStore(link); err == nil {
		s.Close()
		t.Fatal("symlink store accepted")
	}
}
