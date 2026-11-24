//go:build linux

package agentd

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestPinnedHeadAdvanceContextCancelsContendedLocks(t *testing.T) {
	ref, events, authorityKey, signer, sourceKey, now := crashHeadFixture(t)
	for _, sameInstance := range []bool{true, false} {
		name := "file_lock"
		if sameInstance {
			name = "instance_lock"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			first, err := OpenPinnedHeadStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second := first
			if !sameInstance {
				second, err = OpenPinnedHeadStore(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer second.Close()
			}
			floor, candidate := crashHead(events[0]), crashHead(events[1])
			if err := first.Enroll(ref, floor); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(headGrantWireFixture{Schema: pinnedHeadGrantSchema, Ref: ref, Head: candidate, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)})
			if err != nil {
				t.Fatal(err)
			}
			sig := ed25519.Sign(signer, append([]byte(pinnedHeadGrantDomain), raw...))
			if err := first.locked(func(fd int) error {
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				defer cancel()
				result := make(chan error, 1)
				go func() {
					got, err := second.AdvanceContext(ctx, ref, floor, raw, sig, events, authorityKey, sourceKey, now)
					if got != (InspectHead{}) {
						result <- ErrUnverified
						return
					}
					result <- err
				}()
				select {
				case err := <-result:
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Errorf("contended request did not report deadline: %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Error("cancelled request did not return while lock held")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if got, err := first.Read(ref); err != nil || got != floor {
				t.Fatalf("cancelled request changed floor: %+v %v", got, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if got, err := second.AdvanceContext(ctx, ref, floor, raw, sig, events, authorityKey, sourceKey, now); !errors.Is(err, context.Canceled) || got != (InspectHead{}) {
				t.Fatalf("pre-cancelled request not rejected: %+v %v", got, err)
			}
			if got, err := second.AdvanceContext(context.Background(), ref, floor, raw, sig, events, authorityKey, sourceKey, now); err != nil || got != candidate {
				t.Fatalf("fresh request failed after cancellation: %+v %v", got, err)
			}
		})
	}
}
