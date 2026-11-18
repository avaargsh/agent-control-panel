package admission

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

type inputCaptureStore struct {
	captureStore
	raw []byte
}

func (s *inputCaptureStore) CreateWithInput(ctx context.Context, i runintent.Intent, e runpg.Event, raw []byte) (runintent.Intent, bool, error) {
	s.raw = bytes.Clone(raw)
	return s.Create(ctx, i, e)
}

func TestAdmitWithInputComputesDigestBeforeAuthorization(t *testing.T) {
	req, grant := fixture()
	req.RequestDigest = ""
	raw := []byte(`{"prompt":"hello"}`)
	original := bytes.Clone(raw)
	store := &inputCaptureStore{}
	calls := 0
	svc := New(store, resolverFunc(func(_ context.Context, got Request) (Grant, error) {
		calls++
		if got.RequestDigest == "" {
			t.Fatal("resolver received missing digest")
		}
		grant.RequestDigest = got.RequestDigest
		// Simulate a caller retaining and mutating its original slice.
		raw[2] = 'X'
		return grant, nil
	}))
	intent, created, err := svc.AdmitWithInput(context.Background(), req, raw)
	if err != nil || !created || calls != 1 || !bytes.Equal(store.raw, original) {
		t.Fatalf("input admission failed: created=%v calls=%d err=%v", created, calls, err)
	}
	if err := runintent.VerifyExecutionInput(intent, original); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(store.event.Payload, []byte("hello")) {
		t.Fatal("raw input leaked into Outbox")
	}
}

func TestAdmitWithInputRejectsBadDigestAndLegacyStore(t *testing.T) {
	req, _ := fixture()
	store := &inputCaptureStore{}
	resolver := resolverFunc(func(context.Context, Request) (Grant, error) {
		t.Fatal("invalid input reached resolver")
		return Grant{}, nil
	})
	svc := New(store, resolver)
	if _, _, err := svc.AdmitWithInput(context.Background(), req, []byte("{}")); !errors.Is(err, runintent.ErrExecutionInputMismatch) || store.calls != 0 {
		t.Fatalf("client digest trusted: %v", err)
	}
	req.RequestDigest = ""
	if _, _, err := svc.AdmitWithInput(context.Background(), req, []byte("null")); !errors.Is(err, runintent.ErrInvalidExecutionInput) {
		t.Fatalf("invalid input accepted: %v", err)
	}
	legacy := New(&captureStore{}, resolver)
	if _, _, err := legacy.AdmitWithInput(context.Background(), req, []byte("{}")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("legacy store silently accepted input: %v", err)
	}
}
