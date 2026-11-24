//go:build linux

package agentd

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestPinnedHeadAdvanceRejectsGrantExpiredWhileWaitingForLock(t *testing.T) {
	ref, events, authorityKey, signer, sourceKey, now := crashHeadFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	first, err := OpenPinnedHeadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenPinnedHeadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	floor := crashHead(events[0])
	if err := first.Enroll(ref, floor); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(headGrantWireFixture{Schema: "acp.agentd-pinned-head-grant/v1", Ref: ref, Head: crashHead(events[1]), IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(50 * time.Millisecond).Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(signer, append([]byte(pinnedHeadGrantDomain), raw...))
	if _, err := VerifyPinnedHeadExtension(raw, sig, events, ref, floor, authorityKey, sourceKey, now); err != nil {
		t.Fatalf("positive control failed: %v", err)
	}
	result := make(chan error, 1)
	if err := first.locked(func(fd int) error {
		go func() {
			_, err := second.Advance(ref, floor, raw, sig, events, authorityKey, sourceKey, now)
			result <- err
		}()
		// Observe that the competing call owns its instance mutex before
		// letting its grant expire behind the independently held file lock.
		deadline := time.Now().Add(5 * time.Second)
		for second.mu.TryLock() {
			second.mu.Unlock()
			if time.Now().After(deadline) {
				return ErrUnverified
			}
			time.Sleep(time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("grant expired behind file lock still advanced floor")
	}
	if got, err := first.Read(ref); err != nil || got != floor {
		t.Fatalf("expired grant changed floor: %+v %v", got, err)
	}
}
