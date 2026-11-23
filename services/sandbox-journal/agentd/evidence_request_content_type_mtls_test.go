package agentd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
)

// A valid source-signed AgentD Inspect chain must not make ambiguous HTTP
// request metadata trustworthy. The source must reject repeated or conflicting
// Content-Type headers BEFORE consulting the independently pinned Head or DB.
func TestEvidenceMTLSRejectsDuplicateContentTypeBeforePinnedHeadLookup(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	seedAlreadyAuthorizedAttempt(t, db, ref)
	pub, priv := testSourceInspectKey(t)
	event, err := InspectAndJournal(context.Background(), db, ref, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	head := InspectHead{InspectCount: 1, JournalVersion: 1, Digest: event.Digest}
	var lookups atomic.Int32
	server, ca := newAuthenticTLSFixture(t, newEvidenceReaderPool(t, db, ref.TenantID), pub,
		func(_ context.Context, actual Ref) (InspectHead, error) {
			lookups.Add(1)
			if actual != ref {
				return InspectHead{}, ErrMismatch
			}
			return head, nil
		})
	client := clientWithRunIdentity(t, server, ca, ref.TenantID, ref.RunID)
	payload, err := json.Marshal(EvidenceReadRequest{Ref: ref})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		values []string
		want   int
		lookup bool
	}{
		{name: "canonical_single_json", values: []string{"application/json"}, want: http.StatusOK, lookup: true},
		{name: "repeated_identical_json", values: []string{"application/json", "application/json"}, want: http.StatusUnsupportedMediaType},
		{name: "conflicting_second_type", values: []string{"application/json", "text/plain"}, want: http.StatusUnsupportedMediaType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, server.URL+EvidenceReadPath, bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range tc.values {
				req.Header.Add("Content-Type", value)
			}
			before := lookups.Load()
			response, err := client.Do(req)
			if err != nil {
				t.Fatalf("real TLS1.3 client failed: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.want {
				t.Fatalf("signed source accepted ambiguous Content-Type: HTTP %d, want %d", response.StatusCode, tc.want)
			}
			wantLookups := before
			if tc.lookup {
				wantLookups++
			}
			if got := lookups.Load(); got != wantLookups {
				t.Fatalf("untrusted request consulted independent Head: before=%d after=%d want=%d", before, got, wantLookups)
			}
		})
	}
}
