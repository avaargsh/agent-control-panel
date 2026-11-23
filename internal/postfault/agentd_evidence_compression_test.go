package postfault

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// Go's default Transport transparently decompresses a gzip response that it
// negotiated itself. It then removes Content-Encoding, so checking only the
// resulting response header can accidentally accept a compressed evidence
// export despite a strict identity-encoding source contract.
func TestAgentDEvidenceReadRejectsTransparentGzipOverRealMTLS(t *testing.T) {
	_, _, expected, waitRaw, waitSig, events, head, _, _ := g05SourceFixture(t)
	source := agentDEvidenceResponseFixture(t, expected, waitRaw, waitSig, events, head, "EXITED")
	for _, tc := range []struct {
		name       string
		compressed bool
	}{
		{name: "canonical_uncompressed", compressed: false},
		{name: "gzip_even_if_transport_auto_decompresses", compressed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newAgentDEvidenceMTLSServer(t, expected.Ref,
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Cache-Control", "no-store")
					if !tc.compressed {
						_ = json.NewEncoder(w).Encode(source)
						return
					}
					w.Header().Set("Content-Encoding", "gzip")
					writer := gzip.NewWriter(w)
					_ = json.NewEncoder(writer).Encode(source)
					if err := writer.Close(); err != nil {
						t.Errorf("finalize gzip fixture: %v", err)
					}
				}))
			defer server.Close()
			reader := AgentDEvidenceClient{Endpoint: server.URL, HTTPClient: client}
			_, err := reader.Read(context.Background(), expected.Ref, head)
			if tc.compressed && err == nil {
				t.Fatal("a valid signed source export was accepted after HTTP automatically decompressed forbidden gzip encoding")
			}
			if !tc.compressed && err != nil {
				t.Fatalf("uncompressed canonical original source export was rejected: %v", err)
			}
		})
	}
}
