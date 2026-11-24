package authoritycutover

import (
	"context"
	"testing"
)

func TestUnconfiguredPostgresStoreFailsClosed(t *testing.T) {
	store := NewPostgresStore(nil)
	if _, err := store.Observe(context.Background()); err == nil {
		t.Fatal("missing database accepted")
	}
	if _, err := store.Apply(context.Background(), Record{}, Begin, Change{}); err == nil {
		t.Fatal("missing database accepted")
	}
}
