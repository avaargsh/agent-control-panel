package postfault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// An authenticated source can return perfectly valid signed JSON while an
// intermediary injects a second, contradictory wire metadata value. Header.Get
// exposes only the first header value, so the consumer must inspect all values
// before accepting a source evidence response as identity-encoded JSON.
func TestAgentDEvidenceReadRejectsConflictingOrRepeatedWireMetadata(t *testing.T) {
	_, _, expected, waitRaw, waitSig, events, head, _, _ := g05SourceFixture(t)
	evidence := agentDEvidenceResponseFixture(t, expected, waitRaw, waitSig, events, head, "EXITED")
	tests := []struct {
		name         string
		contentTypes []string
		encodings    []string
		allow        bool
	}{
		{name: "canonical_json", contentTypes: []string{"application/json"}, allow: true},
		{name: "explicit_identity", contentTypes: []string{"application/json"}, encodings: []string{"identity"}, allow: true},
		{name: "second_gzip_encoding", contentTypes: []string{"application/json"}, encodings: []string{"identity", "gzip"}},
		{name: "repeated_identity_encoding", contentTypes: []string{"application/json"}, encodings: []string{"identity", "identity"}},
		{name: "second_conflicting_content_type", contentTypes: []string{"application/json", "text/plain"}},
		{name: "repeated_json_content_type", contentTypes: []string{"application/json", "application/json"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newAgentDEvidenceMTLSServer(t, expected.Ref,
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					for _, value := range tc.contentTypes {
						w.Header().Add("Content-Type", value)
					}
					for _, value := range tc.encodings {
						w.Header().Add("Content-Encoding", value)
					}
					w.Header().Set("Cache-Control", "no-store")
					if err := json.NewEncoder(w).Encode(evidence); err != nil {
						t.Errorf("encode authentic signed fixture: %v", err)
					}
				}))
			defer server.Close()

			reader := AgentDEvidenceClient{Endpoint: server.URL, HTTPClient: client}
			_, err := reader.Read(context.Background(), expected.Ref, head)
			if tc.allow && err != nil {
				t.Fatalf("authentic canonical unambiguous response rejected: %v", err)
			}
			if !tc.allow && !errors.Is(err, ErrAgentDEvidenceUnavailable) {
				t.Fatalf("ambiguous source wire metadata passed trust gate: %v", err)
			}
		})
	}
}
