package postfault

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// The original AgentD source exports signed evidence about tenant-scoped
// commands. An unrelated directive containing the substring "no-store" is
// NOT an HTTP Cache-Control no-store directive. Reject it before accepting
// the signed source, even if the rest of the response is otherwise valid.
func TestAgentDEvidenceReadRejectsCacheControlSubstringSpoofing(t *testing.T) {
	_, _, expected, waitRaw, waitSig, events, head, _, _ := g05SourceFixture(t)
	evidence := agentDEvidenceResponseFixture(t, expected, waitRaw, waitSig, events, head, "EXITED")
	for _, tc := range []struct {
		name      string
		directive string
		allowed   bool
	}{
		{"exact", "no-store", true},
		{"case_insensitive", "NO-STORE", true},
		{"comma_separated", "private, no-store", true},
		{"leading_whitespace", "private,  NO-STORE ", true},
		{"missing", "", false},
		{"only_private", "private", false},
		{"prefix_spoof", "x-no-store", false},
		{"assigned_value", "no-store=1", false},
		{"partial_suffix", "public, no-store-ish", false},
		{"only_max_age", "max-age=0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newAgentDEvidenceMTLSServer(t, expected.Ref,
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if tc.directive != "" {
						w.Header().Set("Cache-Control", tc.directive)
					}
					_ = json.NewEncoder(w).Encode(evidence)
				}))
			defer server.Close()

			reader := AgentDEvidenceClient{Endpoint: server.URL, HTTPClient: client}
			_, err := reader.Read(context.Background(), expected.Ref, head)
			if tc.allowed && err != nil {
				t.Fatalf("valid standalone no-store directive rejected: %v", err)
			}
			if !tc.allowed && err == nil {
				t.Fatalf("accepted cacheable evidence with directive %q lacking exact no-store", tc.directive)
			}
		})
	}
}
