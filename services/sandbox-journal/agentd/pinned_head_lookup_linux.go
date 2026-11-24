//go:build linux

package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"time"
)

// HeadGrantProvider retrieves exact independently signed grant bytes from a
// trusted configuration or transport. It must honor the supplied context and
// must not derive the grant or trust key from the source database or request.
type HeadGrantProvider func(context.Context, Ref) ([]byte, []byte, error)

// NewAcceptedHeadLookup adapts the independent local verifier store to the
// existing read-only evidence handler. The provider, clock and both keys are
// trusted operator dependencies; sourceKey must match the handler's source
// verification key. No enrollment or promotion is performed on reads.
// This returns a fresh signed assertion matching the durable floor as of the
// read, not an atomic revocation or publication guarantee. The separate
// fault-bound G05 acceptance statement remains mandatory at the consumer.
func NewAcceptedHeadLookup(store *PinnedHeadStore, authorityKey, sourceKey ed25519.PublicKey,
	provider HeadGrantProvider, clock func() time.Time) (PinnedHeadLookup, error) {
	if store == nil || len(authorityKey) != ed25519.PublicKeySize || len(sourceKey) != ed25519.PublicKeySize ||
		bytes.Equal(authorityKey, sourceKey) || provider == nil || clock == nil {
		return nil, ErrUnverified
	}
	key := bytes.Clone(authorityKey)
	return func(ctx context.Context, expected Ref) (InspectHead, error) {
		if ctx == nil || !expected.valid() {
			return InspectHead{}, ErrUnverified
		}
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := ctx.Err(); err != nil {
			return InspectHead{}, err
		}
		raw, sig, err := provider(ctx, expected)
		if err != nil {
			return InspectHead{}, ErrUnverified
		}
		floor, err := store.ReadContext(ctx, expected)
		if err != nil {
			return InspectHead{}, err
		}
		candidate, err := VerifyPinnedHeadGrant(raw, sig, expected, floor, key, clock())
		if err != nil || candidate != floor {
			return InspectHead{}, ErrUnverified
		}
		if err := ctx.Err(); err != nil {
			return InspectHead{}, err
		}
		return floor, nil
	}, nil
}
