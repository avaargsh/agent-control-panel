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

func TestPinnedHeadLookupRequiresFreshGrantForDurableFloor(t *testing.T) {
	ref, events, authorityKey, signer, sourceKey, now := crashHeadFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenPinnedHeadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	floor, next := crashHead(events[0]), crashHead(events[1])
	mint := func(h InspectHead, issued, expires time.Time) ([]byte, []byte) {
		t.Helper()
		raw, err := json.Marshal(headGrantWireFixture{Schema: pinnedHeadGrantSchema, Ref: ref, Head: h, IssuedAt: issued.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano)})
		if err != nil {
			t.Fatal(err)
		}
		return raw, ed25519.Sign(signer, append([]byte(pinnedHeadGrantDomain), raw...))
	}
	raw, sig := mint(floor, now.Add(-time.Minute), now.Add(time.Minute))
	provider := func(ctx context.Context, actual Ref) ([]byte, []byte, error) {
		if actual != ref {
			return nil, nil, ErrUnverified
		}
		return raw, sig, nil
	}
	lookup, err := NewAcceptedHeadLookup(store, authorityKey, sourceKey, provider, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	assertDenied := func(ctx context.Context, expected Ref) {
		t.Helper()
		if got, err := lookup(ctx, expected); err == nil || got != (InspectHead{}) {
			t.Fatalf("unaccepted lookup returned head: %+v %v", got, err)
		}
	}
	assertDenied(context.Background(), ref) // No automatic enrollment.
	if err := store.Enroll(ref, floor); err != nil {
		t.Fatal(err)
	}
	if got, err := lookup(context.Background(), ref); err != nil || got != floor {
		t.Fatalf("accepted head rejected: %+v %v", got, err)
	}
	raw, sig = mint(next, now.Add(-time.Minute), now.Add(time.Minute))
	assertDenied(context.Background(), ref) // No implicit promotion from a signed candidate.
	if got, err := store.Read(ref); err != nil || got != floor {
		t.Fatalf("lookup mutated floor: %+v %v", got, err)
	}
	if _, err := store.Advance(ref, floor, raw, sig, events, authorityKey, sourceKey, now); err != nil {
		t.Fatal(err)
	}
	if got, err := lookup(context.Background(), ref); err != nil || got != next {
		t.Fatalf("promoted head rejected: %+v %v", got, err)
	}
	raw, sig = mint(floor, now.Add(-time.Minute), now.Add(time.Minute))
	assertDenied(context.Background(), ref)
	raw, sig = mint(next, now.Add(-time.Minute), now)
	assertDenied(context.Background(), ref)
	raw, sig = mint(next, now.Add(-time.Minute), now.Add(time.Minute))
	foreign := ref
	foreign.RunID = "foreign-run"
	assertDenied(context.Background(), foreign)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assertDenied(ctx, ref)
	if _, err := NewAcceptedHeadLookup(store, authorityKey, authorityKey, provider, func() time.Time { return now }); err == nil {
		t.Fatal("shared source and authority key accepted")
	}
	badProvider := func(context.Context, Ref) ([]byte, []byte, error) {
		return nil, nil, errors.New("provider unavailable")
	}
	unavailable, err := NewAcceptedHeadLookup(store, authorityKey, sourceKey, badProvider, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if got, err := unavailable(context.Background(), ref); err == nil || got != (InspectHead{}) {
		t.Fatalf("provider outage returned a head: %+v %v", got, err)
	}
}

func TestPinnedHeadReadContextCancelsContendedLookup(t *testing.T) {
	ref, events, _, _, _, _ := crashHeadFixture(t)
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
	if err := first.locked(func(int) error {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		result := make(chan error, 1)
		go func() {
			got, err := second.ReadContext(ctx, ref)
			if got != (InspectHead{}) {
				result <- ErrUnverified
				return
			}
			result <- err
		}()
		select {
		case err := <-result:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("contended read did not cancel: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("read blocked beyond context deadline")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := second.ReadContext(context.Background(), ref); err != nil || got != floor {
		t.Fatalf("fresh read failed: %+v %v", got, err)
	}
}
