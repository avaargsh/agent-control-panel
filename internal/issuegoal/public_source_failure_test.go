package issuegoal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Failure evidence must retain only provider-neutral metadata, never the
// untrusted GitHub response body, headers, request URL or credentials.
func TestPublicIssueSourceFailureCategoriesAreSafeAndTyped(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		wantReason  string
	}{
		{"not_found", http.StatusNotFound, "application/json", "http_status"},
		{"rate_limited", http.StatusTooManyRequests, "application/json", "http_status"},
		{"provider_unavailable", http.StatusServiceUnavailable, "application/json", "http_status"},
		{"redirect_not_trusted", http.StatusFound, "text/html", "http_status"},
		{"unexpected_media", http.StatusOK, "text/html", "invalid_media"},
		{"invalid_body", http.StatusOK, "application/json", "invalid_body"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := &PublicIssueReader{client: &http.Client{Transport: snapshotRoundTripper(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tc.status,
					Header:     http.Header{"Content-Type": []string{tc.contentType}, "X-Github-Request-Id": []string{"attacker-secret-do-not-log"}},
					Body:       io.NopCloser(strings.NewReader("sensitive-upstream-response")),
				}, nil
			})}}
			_, err := reader.Read(context.Background(), sampleIssueURL)
			var evidence *PublicSourceFailure
			if !errors.Is(err, ErrIssueSourceUnavailable) || !errors.As(err, &evidence) {
				t.Fatalf("missing typed fail-closed Issue observation: %v", err)
			}
			if evidence.Operation != "issue" || evidence.Reason != tc.wantReason || evidence.HTTPStatus != tc.status {
				t.Fatalf("incorrect safe failure classification: %+v", evidence)
			}
			if strings.Contains(err.Error(), "sensitive-upstream-response") ||
				strings.Contains(err.Error(), "attacker-secret") ||
				strings.Contains(err.Error(), "https://") {
				t.Fatal("untrusted provider content leaked into error")
			}
		})
	}
}

func TestPublicSourceTransportFailureDropsUnsafeDriverError(t *testing.T) {
	reader := &PublicIssueReader{client: &http.Client{Transport: snapshotRoundTripper(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("underlying request secret=do-not-log with unsafe URL %s", r.URL)
	})}}
	_, err := reader.Read(context.Background(), sampleIssueURL)
	var evidence *PublicSourceFailure
	if !errors.Is(err, ErrIssueSourceUnavailable) || !errors.As(err, &evidence) ||
		evidence.Reason != "transport" || evidence.Operation != "issue" || evidence.HTTPStatus != 0 {
		t.Fatalf("transport failure not classified: %v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "https://") {
		t.Fatal("underlying transport details leaked into public failure")
	}
}

func TestPublicBaselineSourceFailureCategoriesAreSafeAndTyped(t *testing.T) {
	cases := []struct {
		status      int
		contentType string
		wantReason  string
	}{
		{http.StatusTooManyRequests, "application/json", "http_status"},
		{http.StatusServiceUnavailable, "application/json", "http_status"},
		{http.StatusOK, "text/plain", "invalid_media"},
		{http.StatusOK, "application/json", "invalid_body"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", tc.status, tc.wantReason), func(t *testing.T) {
			reader := &PublicIssueReader{client: &http.Client{Transport: snapshotRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tc.status,
					Header:     http.Header{"Content-Type": []string{tc.contentType}},
					Body:       io.NopCloser(strings.NewReader("private-token-do-not-log")),
				}, nil
			})}}
			_, err := reader.baselineGET(context.Background(), "https://api.github.com/repos/acme/example/branches/main")
			var evidence *PublicSourceFailure
			if !errors.Is(err, ErrBaselineSourceUnavailable) || !errors.As(err, &evidence) ||
				evidence.Operation != "baseline" || evidence.Reason != tc.wantReason || evidence.HTTPStatus != tc.status {
				t.Fatalf("baseline failure not classified: %v", err)
			}
			if strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), "https://") {
				t.Fatal("untrusted provider details leaked into baseline failure")
			}
		})
	}
}
