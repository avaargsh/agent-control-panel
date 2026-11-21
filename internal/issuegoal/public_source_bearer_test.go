package issuegoal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// An explicit, read-only credential must never be obtained from environment
// implicitly. It must only accompany HTTPS calls to the fixed GitHub API
// origin, with redirects disallowed and secret-safe errors.
func TestPublicIssueReaderExplicitBearerIsBoundToGitHubAPI(t *testing.T) {
	const secret = "ci-read-only-private-token"
	reader, err := NewPublicIssueReaderWithBearer(secret)
	if err != nil {
		t.Fatal(err)
	}
	var received int
	reader.client.Transport = snapshotRoundTripper(func(req *http.Request) (*http.Response, error) {
		received++
		if req.URL.Scheme != "https" || req.URL.Host != "api.github.com" ||
			req.Header.Get("Authorization") != "Bearer "+secret {
			t.Fatalf("bearer not bound to GitHub API origin: host=%s", req.URL.Host)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(sampleIssueAPI)),
		}, nil
	})
	if _, err := reader.Read(context.Background(), sampleIssueURL); err != nil || received != 1 {
		t.Fatalf("explicit bearer Issue observation unavailable: %v calls=%d", err, received)
	}
	if _, err := reader.Read(context.Background(), "https://github.com.evil/acme/example/issues/123"); !errors.Is(err, ErrInvalidGoal) ||
		received != 1 {
		t.Fatal("unsafe Issue selector sent a token-bearing network request")
	}
}

func TestPublicBaselineExplicitBearerAndNoUnsafeRedirect(t *testing.T) {
	const secret = "bounded-public-source-token"
	reader, err := NewPublicIssueReaderWithBearer(secret)
	if err != nil {
		t.Fatal(err)
	}
	if reader.client.CheckRedirect == nil {
		t.Fatal("read-only credential client permits redirects")
	}
	calls := 0
	reader.client.Transport = snapshotRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Host != "api.github.com" || req.Header.Get("Authorization") != "Bearer "+secret {
			t.Fatal("baseline request sent auth to non-GitHub origin")
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://attacker.example/steal"}, "Content-Type": []string{"text/html"}},
			Body:       io.NopCloser(strings.NewReader("private-upstream")),
		}, nil
	})
	_, err = reader.baselineGET(context.Background(), "https://api.github.com/repos/acme/example/branches/main")
	if !errors.Is(err, ErrBaselineSourceUnavailable) || calls != 1 {
		t.Fatalf("redirect followed or accepted: %v calls=%d", err, calls)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "attacker.example") {
		t.Fatal("credential or redirect target leaked into failure message")
	}
	if _, err := reader.baselineGET(context.Background(), "https://evil.example/repos/acme/example/branches/main"); !errors.Is(err, ErrInvalidGoal) ||
		calls != 1 {
		t.Fatal("untrusted baseline endpoint used the explicit bearer")
	}
}

func TestPublicIssueBearerRejectsUntrustedCredentialBytes(t *testing.T) {
	for _, bearer := range []string{"", " prefix", "bad\nInjected: header", "bad\rline", "with space",
		"with\tseparator", "bearer:token", strings.Repeat("t", 4097)} {
		t.Run(strings.ReplaceAll(bearer, "\n", "_newline_"), func(t *testing.T) {
			reader, err := NewPublicIssueReaderWithBearer(bearer)
			if !errors.Is(err, ErrInvalidGoal) || reader != nil {
				t.Fatalf("unsafe read credential accepted: %T", reader)
			}
		})
	}
}
