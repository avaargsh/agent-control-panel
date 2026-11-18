package runtimeinspect

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

type dispatchInputFixture struct {
	*recoveryStoreFixture
	raw []byte
	err error
}

func (s *dispatchInputFixture) GetExecutionInput(context.Context, string, string) ([]byte, error) {
	return s.raw, s.err
}

func TestDevelopmentAcceptorUsesPersistedInputAndMutualTLS(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mode         string
		wantStatus   runintent.Status
		wantRequests int64
		wantErr      bool
	}{
		{"accepted", "accepted", runintent.Accepted, 1, false},
		{"conflict", "conflict", runintent.ManualReview, 1, false},
		{"malformed receipt", "malformed", runintent.Unknown, 1, true},
		{"absent response", "absent", runintent.Unknown, 1, true},
		{"redirect", "redirect", runintent.Unknown, 1, true},
		{"storage unavailable", "missing", runintent.Unknown, 0, true},
		{"tampered input", "tampered", runintent.Unknown, 0, true},
		{"wrong TLS peer", "wrong-peer", runintent.Unknown, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(`{ "message": "x<&", "number": 9007199254740993 }`)
			intent := pendingDispatchFixture(t)
			var err error
			intent.RequestDigest, err = runintent.ExecutionInputDigest(intent, input)
			if err != nil {
				t.Fatal(err)
			}
			store := &dispatchInputFixture{recoveryStoreFixture: &recoveryStoreFixture{intent: intent}, raw: input}
			switch tc.mode {
			case "missing":
				store.err = errors.New("input unavailable")
			case "tampered":
				store.raw = []byte("{}")
			}
			roots, serverCert, acpCert := testSPIFFECertificates(t)
			var requests atomic.Int64
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/internal/v2/run-intents:accept" ||
					r.Header.Get("Authorization") != "" || r.Header.Get("X-Forwarded-User") != "" ||
					r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
					t.Error("untrusted or incorrectly routed request")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal(body, &fields) != nil || !bytes.Equal(fields["input"], input) ||
					string(fields["request_digest"]) != fmt.Sprintf("%q", intent.RequestDigest) ||
					!bytes.Contains(fields["principal_context"], []byte(`"subject_id":"subject-1"`)) {
					t.Error("wire input or principal differs from persisted admission")
				}
				w.Header().Set("Content-Type", "application/json")
				switch tc.mode {
				case "conflict":
					w.WriteHeader(http.StatusConflict)
					_, _ = io.WriteString(w, `{"error":"INTENT_CONFLICT"}`)
				case "malformed":
					_, _ = io.WriteString(w, `{"status":"FOUND"}`)
				case "absent":
					_, _ = io.WriteString(w, `{"status":"ABSENT_UNCERTAIN"}`)
				case "redirect":
					http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
				default:
					w.WriteHeader(http.StatusCreated)
					_, _ = fmt.Fprintf(w, `{"status":"FOUND","tenant_id":%q,"run_intent_id":%q,"request_digest":%q,"run_id":%q,"workflow_id":%q,"created":true}`,
						intent.TenantID, intent.ID, intent.RequestDigest, testRunID, "agent-run/v1/"+testRunID)
				}
			}))
			srv.TLS = &tls.Config{
				MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs: roots, Certificates: []tls.Certificate{serverCert},
			}
			srv.StartTLS()
			defer srv.Close()
			peer := "spiffe://example.org/runtime"
			if tc.mode == "wrong-peer" {
				peer = "spiffe://example.org/wrong"
			}
			client, err := NewClient(srv.URL, peer, roots, acpCert)
			if err != nil {
				t.Fatal(err)
			}
			acceptor, err := NewDevelopmentAcceptor(client, store)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DispatchOnce(context.Background(), store, acceptor, intent.TenantID, intent.ID, "worker", time.Minute)
			if got.Status != tc.wantStatus || (err != nil) != tc.wantErr || requests.Load() != tc.wantRequests {
				t.Fatalf("dispatch status=%s err=%v requests=%d", got.Status, err, requests.Load())
			}
			if tc.mode == "conflict" && got.ManualReviewCode != "RUNTIME_INTENT_CONFLICT" {
				t.Fatalf("conflict not quarantined: %+v", got)
			}
			if got.Status == runintent.Unknown || got.Status == runintent.ManualReview {
				_, err = DispatchOnce(context.Background(), store, acceptor, intent.TenantID, intent.ID, "worker-2", time.Minute)
				if !errors.Is(err, ErrNotDispatchable) || requests.Load() != tc.wantRequests {
					t.Fatalf("failed dispatch retried: %v", err)
				}
			}
		})
	}
}

func TestDevelopmentAcceptorRefusesUnclaimedOrStaleIntent(t *testing.T) {
	intent := pendingDispatchFixture(t)
	raw := []byte("{}")
	intent.RequestDigest, _ = runintent.ExecutionInputDigest(intent, raw)
	store := &dispatchInputFixture{recoveryStoreFixture: &recoveryStoreFixture{intent: intent}, raw: raw}
	roots, _, acpCert := testSPIFFECertificates(t)
	client, err := NewClient("https://127.0.0.1:1", "spiffe://example.org/runtime", roots, acpCert)
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := NewDevelopmentAcceptor(client, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acceptor.Accept(context.Background(), intent); !errors.Is(err, ErrNotDispatchable) {
		t.Fatalf("unclaimed intent accepted: %v", err)
	}
	claimed, err := intent.ClaimDispatch(intent.Version, "worker", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store.intent = claimed
	forged := claimed
	forged.PrincipalSnapshot.ConfigDigest = "sha256:" + strings.Repeat("c", 64)
	if _, err := acceptor.Accept(context.Background(), forged); !errors.Is(err, ErrNotDispatchable) {
		t.Fatalf("stale/forged claim accepted: %v", err)
	}
}
