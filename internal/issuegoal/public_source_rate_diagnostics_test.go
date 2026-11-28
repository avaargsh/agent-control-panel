package issuegoal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPublicSourceNumericRateDiagnostics(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header http.Header
		want   []string
	}{
		{"forbidden_zero", 403, http.Header{"X-Ratelimit-Remaining": {"0"}, "Retry-After": {"12"}}, []string{"rate_remaining=0", "retry_after_seconds=12"}},
		{"too_many_requests", 429, http.Header{"X-Ratelimit-Remaining": {"17"}, "Retry-After": {"30"}}, []string{"rate_remaining=17", "retry_after_seconds=30"}},
		{"unavailable", 503, http.Header{"Retry-After": {"5"}}, []string{"retry_after_seconds=5"}},
		{"missing", 403, nil, nil},
		{"duplicate", 429, http.Header{"X-Ratelimit-Remaining": {"0", "1"}, "Retry-After": {"2", "3"}}, nil},
		{"injection", 403, http.Header{"X-Ratelimit-Remaining": {"0 secret-marker"}, "Retry-After": {"https://secret-marker.invalid/"}}, nil},
		{"overflow", 429, http.Header{"X-Ratelimit-Remaining": {"99999999999999999999"}, "Retry-After": {"86401"}}, nil},
		{"not_rate_status", 404, http.Header{"X-Ratelimit-Remaining": {"0"}, "Retry-After": {"1"}}, nil},
		{"signed_or_date", 503, http.Header{"Retry-After": {"+1"}}, nil},
		{"date", 503, http.Header{"Retry-After": {"Wed, 21 Oct 2015 07:28:00 GMT"}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, operation := range []string{"issue", "baseline"} {
				t.Run(operation, func(t *testing.T) {
					reader := &PublicIssueReader{client: &http.Client{Transport: snapshotRoundTripper(func(*http.Request) (*http.Response, error) {
						header := tc.header.Clone()
						if header == nil {
							header = make(http.Header)
						}
						header.Set("Content-Type", "application/json")
						header.Set("X-Github-Request-Id", "secret-marker")
						return &http.Response{StatusCode: tc.status, Header: header, Body: io.NopCloser(strings.NewReader("secret-marker"))}, nil
					})}}
					cause := ErrIssueSourceUnavailable
					var err error
					if operation == "issue" {
						_, err = reader.Read(context.Background(), sampleIssueURL)
					} else {
						cause = ErrBaselineSourceUnavailable
						_, err = reader.baselineGET(context.Background(), "https://api.github.com/repos/acme/example/branches/main")
					}
					var failure *PublicSourceFailure
					if !errors.Is(err, cause) || !errors.As(err, &failure) || failure.HTTPStatus != tc.status || failure.Operation != operation {
						t.Fatalf("failure lost typed classification: %v", err)
					}
					msg := err.Error()
					for _, want := range tc.want {
						if !strings.Contains(msg, want) {
							t.Errorf("missing safe numeric diagnostic %q: %s", want, msg)
						}
					}
					for _, prefix := range []string{"rate_remaining=", "retry_after_seconds="} {
						want := false
						for _, value := range tc.want {
							want = want || strings.HasPrefix(value, prefix)
						}
						if strings.Contains(msg, prefix) != want {
							t.Errorf("unexpected diagnostic presence %q: %s", prefix, msg)
						}
					}
					if strings.Contains(msg, "secret-marker") || strings.Contains(msg, "https://") {
						t.Fatal("untrusted provider metadata leaked")
					}
				})
			}
		})
	}
}
