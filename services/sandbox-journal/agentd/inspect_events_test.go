package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testSourceInspectKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestInspectSourcePersistsUnknownHoldAndHashLinkedFreshEvents(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	seedAlreadyAuthorizedAttempt(t, db, ref)
	pub, priv := testSourceInspectKey(t)
	var events []JournaledInspection
	for i := 1; i <= 2; i++ {
		event, err := InspectAndJournal(context.Background(), db, ref, pub, priv)
		if err != nil || event.Result.State != Unknown || event.Result.NextAction != Hold ||
			event.Result.CanRetry || event.Result.CanDeclareReleased ||
			event.Event.InspectCount != uint64(i) || event.Event.JournalVersion != uint64(i) ||
			event.Event.ExitReceiptDigest != "" || event.Digest == "" ||
			len(event.Signature) != ed25519.SignatureSize {
			t.Fatalf("inspect %d was not durable UNKNOWN/HOLD: %+v error=%v", i, event, err)
		}
		events = append(events, event)
	}
	if err := VerifyInspectChain(events, ref, pub, time.Now().UTC()); err != nil {
		t.Fatalf("valid persistent signed UNKNOWN inspection chain rejected: %v", err)
	}
	// A fresh connection must see source journal, not a caller-provided count.
	other, err := pgxpool.New(context.Background(), os.Getenv("SANDBOX_JOURNAL_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	persisted, err := LoadInspectChain(context.Background(), other, ref, pub, time.Now().UTC())
	if err != nil || len(persisted) != 2 ||
		!bytes.Equal(persisted[0].Payload, events[0].Payload) ||
		!bytes.Equal(persisted[1].Signature, events[1].Signature) {
		t.Fatalf("fresh source reader cannot replay durable unknown inspections: count=%d err=%v", len(persisted), err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	third, err := InspectAndJournal(context.Background(), other, ref, pub, priv)
	if err != nil || third.Event.InspectCount != 3 || third.Result.State != Unknown || third.Result.CanRetry {
		t.Fatalf("SIGKILL + absent terminal must stay UNKNOWN/HOLD: %+v %v", third, err)
	}
	if err := VerifyInspectChain(append(events, third), ref, pub, time.Now().UTC()); err != nil {
		t.Fatalf("post-SIGKILL signed journal chain cannot be verified: %v", err)
	}
}

func TestInspectSourceTerminalCommitBindsWaitDigestAndMonotonicRevision(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "0.2")
	seedAlreadyAuthorizedAttempt(t, db, ref)
	pub, priv := testSourceInspectKey(t)
	pre, err := InspectAndJournal(context.Background(), db, ref, pub, priv)
	if err != nil || pre.Result.State != Unknown {
		t.Fatalf("pre-Wait inspection must HOLD: %+v %v", pre, err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("expected original non-zero child Wait")
	}
	if _, err := RecordWaitOutcome(context.Background(), db, ref, cmd.ProcessState, priv); err != nil {
		t.Fatal(err)
	}
	post, err := InspectAndJournal(context.Background(), db, ref, pub, priv)
	if err != nil || post.Result.State != FailedConfirmed ||
		post.Event.State != FailedConfirmed || post.Event.ExitReceiptDigest != post.Result.ExitReceiptDigest ||
		post.Event.InspectCount != 2 || post.Event.JournalVersion <= pre.Event.JournalVersion ||
		post.Event.PreviousDigest != pre.Digest || post.Result.CanRetry ||
		post.Result.CanDeclareReleased {
		t.Fatalf("post-Wait Inspect journal not tied to original committed terminal: %+v %v", post, err)
	}
	persisted, err := LoadInspectChain(context.Background(), db, ref, pub, time.Now().UTC())
	if err != nil || len(persisted) != 2 || persisted[1].Digest != post.Digest {
		t.Fatalf("cannot independently read source terminal inspection: %+v %v", persisted, err)
	}
}

func TestInspectSourceRejectsForeignAttemptAndUntrustedSignerBeforeMinting(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	seedAlreadyAuthorizedAttempt(t, db, ref)
	pub, priv := testSourceInspectKey(t)
	bad := ref
	bad.RunID = "different-run"
	if _, err := InspectAndJournal(context.Background(), db, bad, pub, priv); !errors.Is(err, ErrMismatch) {
		t.Fatalf("foreign Run permitted source inspection: %v", err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectAndJournal(context.Background(), db, ref, other, priv); !errors.Is(err, ErrUnverified) {
		t.Fatalf("inspector minted event with signer/key mismatch: %v", err)
	}
	var n int
	if err := db.QueryRow(context.Background(), "SELECT count(*) FROM public.sandbox_agentd_inspect_events").Scan(&n); err != nil || n != 0 {
		t.Fatalf("unauthorized inspection advanced journal count: %d %v", n, err)
	}
}

func TestInspectSourceVerifierDetectsReorderedTamperedAndReboundEvents(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	seedAlreadyAuthorizedAttempt(t, db, ref)
	pub, priv := testSourceInspectKey(t)
	first, err := InspectAndJournal(context.Background(), db, ref, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectAndJournal(context.Background(), db, ref, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	samples := []struct {
		name string
		edit func([]JournaledInspection) []JournaledInspection
	}{
		{"missing_first", func(s []JournaledInspection) []JournaledInspection { return s[1:] }},
		{"reverse", func(s []JournaledInspection) []JournaledInspection { s[0], s[1] = s[1], s[0]; return s }},
		{"altered_bytes", func(s []JournaledInspection) []JournaledInspection {
			s[1].Payload = append(append([]byte(nil), s[1].Payload...), ' ')
			return s
		}},
		{"wrong_digest", func(s []JournaledInspection) []JournaledInspection {
			s[1].Digest = "sha256:" + string(bytes.Repeat([]byte("f"), 64))
			return s
		}},
		{"wrong_signature", func(s []JournaledInspection) []JournaledInspection {
			s[1].Signature = make([]byte, ed25519.SignatureSize)
			return s
		}},
		{"rebound_attempt", func(s []JournaledInspection) []JournaledInspection {
			s[0].Event.Ref.AttemptID = "changed-attempt"
			return s
		}},
		{"count_rollback", func(s []JournaledInspection) []JournaledInspection { s[1].Event.InspectCount = 1; return s }},
	}
	for _, tc := range samples {
		t.Run(tc.name, func(t *testing.T) {
			evs := tc.edit([]JournaledInspection{first, second})
			if err := VerifyInspectChain(evs, ref, pub, now); err == nil {
				t.Fatal("untrusted, reordered or incomplete signed inspection journal accepted")
			}
		})
	}
	if _, err := db.Exec(context.Background(), "DELETE FROM public.sandbox_agentd_inspect_events"); err == nil {
		t.Fatal("source inspect events are not append-only")
	}
}
