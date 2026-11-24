package agentd

import (
	"bytes"
	"crypto/ed25519"
	"time"
)

// VerifyPinnedHeadExtension authenticates the candidate grant and the complete
// source chain, then checks that the independently accepted floor is still at
// its original ordinal. The authority and source keys must be distinct and
// configured independently of the grant and source. The returned head is only
// a verified candidate for a subsequent durable compare-and-swap operation;
// this function does not persist a floor or grant execution authority.
func VerifyPinnedHeadExtension(raw, signature []byte, events []JournaledInspection,
	expected Ref, floor InspectHead, authorityKey, sourceKey ed25519.PublicKey,
	now time.Time) (InspectHead, error) {
	if len(sourceKey) != ed25519.PublicKeySize || bytes.Equal(authorityKey, sourceKey) {
		return InspectHead{}, ErrUnverified
	}
	candidate, err := VerifyPinnedHeadGrant(raw, signature, expected, floor, authorityKey, now)
	if err != nil {
		return InspectHead{}, ErrUnverified
	}
	if err := VerifyInspectAtHead(events, expected, sourceKey, now, candidate); err != nil {
		return InspectHead{}, ErrUnverified
	}
	if floor.InspectCount > uint64(len(events)) {
		return InspectHead{}, ErrUnverified
	}
	row := events[floor.InspectCount-1]
	if row.Event.InspectCount != floor.InspectCount || row.Event.JournalVersion != floor.JournalVersion || row.Digest != floor.Digest {
		return InspectHead{}, ErrUnverified
	}
	return candidate, nil
}
