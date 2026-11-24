//go:build linux

package agentd

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// Real PostgreSQL/OS source + authentic mTLS transport. The independent
// grant publisher is an ephemeral fixture, not a deployed issuer.
func TestEvidenceMTLSUsesDurablyAcceptedHeadLookup(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	seedAlreadyAuthorizedAttempt(t, db, ref)
	sourceKey, sourceSigner := testSourceInspectKey(t)
	authorityKey, authoritySigner := testSourceInspectKey(t)
	ctx := context.Background()
	first, err := InspectAndJournal(ctx, db, ref, sourceKey, sourceSigner)
	if err != nil {
		t.Fatal(err)
	}
	floor := crashHead(first)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenPinnedHeadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	type grantPair struct {
		raw []byte
		sig []byte
	}
	var grant atomic.Pointer[grantPair]
	mint := func(head InspectHead) *grantPair {
		t.Helper()
		now := time.Now().UTC()
		raw, err := json.Marshal(headGrantWireFixture{Schema: pinnedHeadGrantSchema, Ref: ref, Head: head, IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)})
		if err != nil {
			t.Fatal(err)
		}
		return &grantPair{raw: raw, sig: ed25519.Sign(authoritySigner, append([]byte(pinnedHeadGrantDomain), raw...))}
	}
	initial := mint(floor)
	grant.Store(initial)
	lookup, err := NewAcceptedHeadLookup(store, authorityKey, sourceKey, func(ctx context.Context, actual Ref) ([]byte, []byte, error) {
		current := grant.Load()
		if actual != ref || current == nil || ctx.Err() != nil {
			return nil, nil, ErrUnverified
		}
		return current.raw, current.sig, nil
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	server, ca := newAuthenticTLSFixture(t, newEvidenceReaderPool(t, db, ref.TenantID), sourceKey, lookup)
	client := clientWithRunIdentity(t, server, ca, ref.TenantID, ref.RunID)
	if status, _ := fetchOriginalEvidence(t, client, server, ref); status != http.StatusServiceUnavailable {
		t.Fatalf("unenrolled source returned HTTP %d", status)
	}
	if err := store.Enroll(ref, floor); err != nil {
		t.Fatal(err)
	}
	if status, response := fetchOriginalEvidence(t, client, server, ref); status != http.StatusOK || response.Head != floor || response.State != Unknown || response.CanRetry || response.Terminal != nil {
		t.Fatalf("accepted initial Head unavailable: %d %+v", status, response)
	}
	second, err := InspectAndJournal(ctx, db, ref, sourceKey, sourceSigner)
	if err != nil {
		t.Fatal(err)
	}
	next := crashHead(second)
	newGrant := mint(next)
	grant.Store(newGrant)
	if status, _ := fetchOriginalEvidence(t, client, server, ref); status != http.StatusServiceUnavailable {
		t.Fatalf("signed but unaccepted Head returned HTTP %d", status)
	}
	if got, err := store.Read(ref); err != nil || got != floor {
		t.Fatalf("HTTP read promoted floor: %+v %v", got, err)
	}
	if _, err := store.AdvanceContext(ctx, ref, floor, newGrant.raw, newGrant.sig, []JournaledInspection{first, second}, authorityKey, sourceKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	if status, response := fetchOriginalEvidence(t, client, server, ref); status != http.StatusOK || response.Head != next || len(response.Inspections) != 2 || response.State != Unknown || response.NextAction != Hold || response.CanRetry || response.Terminal != nil {
		t.Fatalf("accepted extension unavailable: %d %+v", status, response)
	}
	grant.Store(initial)
	if status, _ := fetchOriginalEvidence(t, client, server, ref); status != http.StatusServiceUnavailable {
		t.Fatalf("old grant replay returned HTTP %d", status)
	}
	grant.Store(nil)
	if status, _ := fetchOriginalEvidence(t, client, server, ref); status != http.StatusServiceUnavailable {
		t.Fatalf("missing independent provider returned HTTP %d", status)
	}
	var count int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM public.sandbox_agentd_inspect_events").Scan(&count); err != nil || count != 2 {
		t.Fatalf("HTTP read mutated source journal: %d %v", count, err)
	}
}
