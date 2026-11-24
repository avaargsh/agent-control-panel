package agentd

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"regexp"
	"time"
)

const (
	pinnedHeadGrantSchema      = "acp.agentd-pinned-head-grant/v1"
	pinnedHeadGrantDomain      = pinnedHeadGrantSchema + "\x00"
	maxPinnedHeadGrantBytes    = 8192
	maxPinnedHeadGrantLifetime = 5 * time.Minute
)

var pinnedHeadDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type pinnedHeadGrant struct {
	Schema    string      `json:"schema"`
	Ref       Ref         `json:"ref"`
	Head      InspectHead `json:"head"`
	IssuedAt  string      `json:"issued_at"`
	ExpiresAt string      `json:"expires_at"`
}

func validPinnedHead(h InspectHead) bool {
	return h.InspectCount > 0 && h.InspectCount <= maxInspectEvents &&
		h.JournalVersion == h.InspectCount && pinnedHeadDigest.MatchString(h.Digest)
}

// VerifyPinnedHeadGrant authenticates a candidate head against an independently
// configured authority key and an already accepted head for expected. Neither
// the key nor the floor may come from the untrusted grant or source database.
// A higher head is not an accepted extension: callers must verify the entire
// source chain including the floor digest at its original ordinal and persist
// the new floor with CAS. This function does not authorize dispatch or release.
func VerifyPinnedHeadGrant(raw, signature []byte, expected Ref, floor InspectHead,
	key ed25519.PublicKey, now time.Time) (InspectHead, error) {
	if len(raw) == 0 || len(raw) > maxPinnedHeadGrantBytes ||
		len(signature) != ed25519.SignatureSize || len(key) != ed25519.PublicKeySize ||
		!expected.valid() || !validPinnedHead(floor) || now.IsZero() ||
		!ed25519.Verify(key, append([]byte(pinnedHeadGrantDomain), raw...), signature) {
		return InspectHead{}, ErrUnverified
	}
	var grant pinnedHeadGrant
	if err := json.Unmarshal(raw, &grant); err != nil {
		return InspectHead{}, ErrUnverified
	}
	canonical, err := json.Marshal(grant)
	if err != nil || !bytes.Equal(canonical, raw) || grant.Schema != pinnedHeadGrantSchema ||
		grant.Ref != expected || !validPinnedHead(grant.Head) ||
		grant.Head.InspectCount < floor.InspectCount ||
		(grant.Head.InspectCount == floor.InspectCount && grant.Head != floor) {
		return InspectHead{}, ErrUnverified
	}
	issued, err := time.Parse(time.RFC3339Nano, grant.IssuedAt)
	if err != nil || issued.IsZero() || issued.UTC().Format(time.RFC3339Nano) != grant.IssuedAt {
		return InspectHead{}, ErrUnverified
	}
	expires, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil || expires.UTC().Format(time.RFC3339Nano) != grant.ExpiresAt ||
		issued.After(now) || !expires.After(now) || !expires.After(issued) ||
		expires.Sub(issued) > maxPinnedHeadGrantLifetime {
		return InspectHead{}, ErrUnverified
	}
	return grant.Head, nil
}
