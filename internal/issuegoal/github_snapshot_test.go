package issuegoal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

const sampleIssueURL = "https://github.com/acme/example/issues/123"
const sampleIssueAPI = `{"id":98765,"number":123,"html_url":"https://github.com/acme/example/issues/123","repository_url":"https://api.github.com/repos/acme/example","title":"Fix idempotency","body":"Observed behavior","state":"open","updated_at":"2026-11-21T01:00:00Z"}`

type snapshotRoundTripper func(*http.Request) (*http.Response, error)

func (f snapshotRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func stubIssueReader(t *testing.T, body string, code int, media string) *PublicIssueReader {
	t.Helper()
	return &PublicIssueReader{client: &http.Client{Transport: snapshotRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet ||
			r.URL.String() != "https://api.github.com/repos/acme/example/issues/123" ||
			r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Fatalf("untrusted outbound request: %s %s", r.Method, r.URL)
		}
		return &http.Response{
			StatusCode: code, Header: http.Header{"Content-Type": []string{media}},
			Body: io.NopCloser(strings.NewReader(body)),
		}, nil
	})}}
}

func TestPublicIssueReaderCanonicalDigestAndChangeDetection(t *testing.T) {
	reader := stubIssueReader(t, sampleIssueAPI, http.StatusOK, "application/json")
	snapshot, err := reader.Read(context.Background(), sampleIssueURL)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Schema != IssueSnapshotVersion || snapshot.IssueURL != sampleIssueURL ||
		snapshot.IssueID != 98765 || snapshot.Number != 123 || snapshot.Title == "" {
		t.Fatalf("invalid snapshot: %+v", snapshot)
	}
	if snapshot.Digest != "sha256:03f1da8b1b8088a5a3c42dc1b4c1e9eb2a9e4a184d274c72478a61f847e53439" {
		t.Fatalf("canonical preimage vector changed: %s", snapshot.Digest)
	}
	repeated, err := reader.Read(context.Background(), sampleIssueURL)
	if err != nil || repeated.Digest != snapshot.Digest {
		t.Fatalf("nondeterministic digest: %v", err)
	}
	modified := strings.Replace(sampleIssueAPI, "Observed behavior", "Updated behavior", 1)
	changed, err := stubIssueReader(t, modified, http.StatusOK, "application/json").Read(context.Background(), sampleIssueURL)
	if err != nil || changed.Digest == snapshot.Digest {
		t.Fatalf("content changed without digest change: %v", err)
	}
	if err := reader.Verify(context.Background(), sampleIssueURL, snapshot.Digest); err != nil {
		t.Fatal(err)
	}
	if err := reader.Verify(context.Background(), sampleIssueURL, changed.Digest); !errors.Is(err, ErrIssueSnapshotMismatch) {
		t.Fatalf("stale digest accepted: %v", err)
	}
}

func TestPublicIssueReaderRejectsUntrustedResponses(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		code int
		mime string
	}{
		"pull request response": {strings.Replace(sampleIssueAPI, `"state":"open"`, `"pull_request":{"url":"/pull/123"},"state":"open"`, 1), 200, "application/json"},
		"cross repo response":   {strings.Replace(sampleIssueAPI, "acme/example\"", "attacker/other\"", 1), 200, "application/json"},
		"url mismatch":          {strings.Replace(sampleIssueAPI, "/issues/123\"", "/issues/124\"", 1), 200, "application/json"},
		"number mismatch":       {strings.Replace(sampleIssueAPI, `"number":123`, `"number":124`, 1), 200, "application/json"},
		"duplicate keys":        {strings.Replace(sampleIssueAPI, `"title":`, `"title":"fake","title":`, 1), 200, "application/json"},
		"casefold keys":         {strings.Replace(sampleIssueAPI, `"title":`, `"Title":"fake","title":`, 1), 200, "application/json"},
		"missing ID":            {strings.Replace(sampleIssueAPI, `"id":98765`, `"id":0`, 1), 200, "application/json"},
		"bad time":              {strings.Replace(sampleIssueAPI, "2026-11-21T01:00:00Z", "yesterday", 1), 200, "application/json"},
		"bad status":            {strings.Replace(sampleIssueAPI, `"state":"open"`, `"state":"x"`, 1), 200, "application/json"},
		"not found":             {sampleIssueAPI, 404, "application/json"},
		"wrong media":           {sampleIssueAPI, 200, "text/html"},
		"oversized response":    {strings.Repeat("A", 128*1024+1), 200, "application/json"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := stubIssueReader(t, tc.body, tc.code, tc.mime).Read(context.Background(), sampleIssueURL); err == nil {
				t.Fatal("untrusted GitHub response produced valid Issue snapshot")
			}
		})
	}
}

func TestPublicIssueReaderRejectsUnsafeURLsBeforeNetwork(t *testing.T) {
	for _, issueURL := range []string{
		"http://github.com/acme/example/issues/123",
		"https://github.com.evil/acme/example/issues/123",
		"https://github.com/acme/example/issues/123?token=x",
		"https://github.com/acme/example/pull/123",
		"https://github.com/acme/example/issues/%31%32%33",
		"https://github.com/acme/../issues/123",
		"https://github.com/acme/./issues/123",
	} {
		if _, err := stubIssueReader(t, sampleIssueAPI, 200, "application/json").Read(context.Background(), issueURL); err == nil {
			t.Fatalf("unsafe URL accepted: %s", issueURL)
		}
	}
}
