package issuegoal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

const testExperimentSHA = "1111111111111111111111111111111111111111"
const testIntegrationSHA = "2222222222222222222222222222222222222222"

func baselineFixture(t *testing.T, branch, headSHA, commitSHA string, code int) (*PublicIssueReader, *[]string) {
	t.Helper()
	calls := new([]string)
	reader := &PublicIssueReader{client: &http.Client{Transport: snapshotRoundTripper(func(req *http.Request) (*http.Response, error) {
		*calls = append(*calls, req.URL.String())
		if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "api.github.com" || req.Header.Get("Accept") != "application/vnd.github+json" {
			t.Fatalf("unsafe baseline request: %v", req.URL)
		}
		var body string
		switch req.URL.Path {
		case "/repos/acme/example/branches/" + branch:
			body = `{"name":"` + branch + `","commit":{"sha":"` + headSHA + `"},"protected":false}`
		case "/repos/acme/example/git/commits/" + testExperimentSHA, "/repos/acme/example/git/commits/" + testIntegrationSHA:
			body = `{"sha":"` + commitSHA + `"}`
			if commitSHA == "" {
				body = `{"sha":"` + strings.TrimPrefix(req.URL.Path, "/repos/acme/example/git/commits/") + `"}`
			}
		default:
			t.Fatalf("request to unexpected endpoint: %v", req.URL)
		}
		return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	return reader, calls
}

func TestInspectBaselinesRequiresCurrentBranchHeadAndExactCommits(t *testing.T) {
	r, calls := baselineFixture(t, "main", testIntegrationSHA, "", 200)
	observation, err := r.InspectBaselines(context.Background(), sampleIssueURL, "main", testExperimentSHA, testIntegrationSHA)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Schema != PublicBaselineInspectionVersion || observation.TargetBranch != "main" ||
		observation.ObservedBranchHeadSHA != testIntegrationSHA || observation.BranchProtected || len(*calls) != 3 {
		t.Fatalf("incomplete baseline observation: %#v / %#v", observation, *calls)
	}
	same, sameCalls := baselineFixture(t, "main", testIntegrationSHA, "", 200)
	if _, err := same.InspectBaselines(context.Background(), sampleIssueURL, "main", testIntegrationSHA, testIntegrationSHA); err != nil || len(*sameCalls) != 2 {
		t.Fatalf("same-SHA commit must be verified once: %v %#v", err, *sameCalls)
	}
}

func TestInspectBaselinesRejectsMutableOrWrongSource(t *testing.T) {
	cases := map[string]struct {
		branch, headSHA, commitSHA string
		code                       int
		expected                   error
	}{
		"branch moved":            {"main", testExperimentSHA, "", 200, ErrBaselineMismatch},
		"wrong commit identity":   {"main", testIntegrationSHA, testExperimentSHA, 200, ErrBaselineMismatch},
		"API unavailable":         {"main", testIntegrationSHA, "", 404, ErrBaselineSourceUnavailable},
		"redirect not acceptance": {"main", testIntegrationSHA, "", 302, ErrBaselineSourceUnavailable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			reader, _ := baselineFixture(t, tc.branch, tc.headSHA, tc.commitSHA, tc.code)
			_, err := reader.InspectBaselines(context.Background(), sampleIssueURL, tc.branch, testExperimentSHA, testIntegrationSHA)
			if !errors.Is(err, tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, err)
			}
		})
	}
}

func TestInspectBaselinesValidatesSelectorsBeforeNetwork(t *testing.T) {
	bad := []struct{ issueURL, branch, experiment, integration string }{
		{"https://github.com.evil/acme/example/issues/123", "main", testExperimentSHA, testIntegrationSHA},
		{sampleIssueURL, "../main", testExperimentSHA, testIntegrationSHA},
		{sampleIssueURL, "main", "main", testIntegrationSHA},
		{sampleIssueURL, "main", testExperimentSHA, strings.Repeat("A", 40)},
	}
	reader, calls := baselineFixture(t, "main", testIntegrationSHA, "", 200)
	for _, input := range bad {
		if _, err := reader.InspectBaselines(context.Background(), input.issueURL, input.branch, input.experiment, input.integration); !errors.Is(err, ErrInvalidGoal) {
			t.Fatalf("unsafe selectors accepted: %+v / %v", input, err)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("invalid selectors sent API requests: %v", *calls)
	}
}
