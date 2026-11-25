package authoritycutover

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresBarrierFailsClosedWithoutPool(t *testing.T) {
	barrier := NewPostgresBarrier(nil, "observer-login", ObserverRole)
	if _, err := barrier.Acquire(context.Background()); !errors.Is(err, ErrBarrierUnavailable) {
		t.Fatalf("missing observer pool was not rejected: %v", err)
	}

	change := Change{ID: "change-a", ManifestDigest: "sha256:" + strings.Repeat("a", 64), Operator: "operator-a"}
	expected := Record{Generation: 1, Revision: 2, Phase: Draining, Change: change}
	if _, err := barrier.AcquireCutover(context.Background(), expected); !errors.Is(err, ErrBarrierUnavailable) {
		t.Fatalf("missing coordinator pool was not rejected: %v", err)
	}

	// A non-nil pool does not make an empty or mismatched identity valid.
	emptyIdentity := NewPostgresBarrier((*pgxpool.Pool)(nil), "", ObserverRole)
	if _, err := emptyIdentity.Acquire(context.Background()); !errors.Is(err, ErrBarrierUnavailable) {
		t.Fatalf("empty LOGIN was not rejected: %v", err)
	}
}
