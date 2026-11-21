package issuegoal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

const (
	PublicBaselineInspectionVersion = "acp.github-baselines-inspection/v1"
	maxBaselineResponseBytes        = 128 * 1024
)

var (
	ErrBaselineSourceUnavailable = errors.New("GitHub baseline source unavailable")
	ErrBaselineMismatch          = errors.New("GitHub baseline does not match requested repository or branch")
)

// PublicBaselineInspection is a live, read-only observation; it is not a
// GitHub attestation, authorization grant, immutable retention or Permit.
type PublicBaselineInspection struct {
	Schema                 string `json:"schema"`
	IssueURL               string `json:"issue_url"`
	TargetBranch           string `json:"target_branch"`
	ExperimentBaselineSHA  string `json:"experiment_baseline_sha"`
	IntegrationBaselineSHA string `json:"integration_baseline_sha"`
	ObservedBranchHeadSHA  string `json:"observed_branch_head_sha"`
	BranchProtected        bool   `json:"branch_protected"`
}

// InspectBaselines checks that the target branch currently points at the
// requested integration baseline and both exact commit SHA objects exist in
// the Issue's repository. It does not claim SHA ancestry or private access.
func (r *PublicIssueReader) InspectBaselines(ctx context.Context, issueURL, branch, experimentSHA, integrationSHA string) (PublicBaselineInspection, error) {
	if r == nil || r.client == nil || !validGitHubIssueURL(issueURL) ||
		!validBranch(branch) || !validHex(experimentSHA, 40) || !validHex(integrationSHA, 40) {
		return PublicBaselineInspection{}, ErrInvalidGoal
	}
	parts := strings.Split(issueURL, "/")
	base := "https://api.github.com/repos/" + url.PathEscape(parts[3]) + "/" + url.PathEscape(parts[4])
	branchBody, err := r.baselineGET(ctx, base+"/branches/"+url.PathEscape(branch))
	if err != nil {
		return PublicBaselineInspection{}, err
	}
	var observedBranch struct {
		Name   string `json:"name"`
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
		Protected bool `json:"protected"`
	}
	if json.Unmarshal(branchBody, &observedBranch) != nil || observedBranch.Name != branch ||
		observedBranch.Commit.SHA != integrationSHA {
		return PublicBaselineInspection{}, ErrBaselineMismatch
	}
	// Do not mint a second identity for the same commit or claim a ref is
	// verified merely because its SHA resembles 40 hex characters.
	commits := []string{experimentSHA}
	if integrationSHA != experimentSHA {
		commits = append(commits, integrationSHA)
	}
	for _, sha := range commits {
		body, err := r.baselineGET(ctx, base+"/git/commits/"+sha)
		if err != nil {
			return PublicBaselineInspection{}, err
		}
		var commit struct {
			SHA string `json:"sha"`
		}
		if json.Unmarshal(body, &commit) != nil || commit.SHA != sha {
			return PublicBaselineInspection{}, ErrBaselineMismatch
		}
	}
	return PublicBaselineInspection{
		Schema: PublicBaselineInspectionVersion, IssueURL: issueURL,
		TargetBranch: branch, ExperimentBaselineSHA: experimentSHA,
		IntegrationBaselineSHA: integrationSHA,
		ObservedBranchHeadSHA:  observedBranch.Commit.SHA,
		BranchProtected:        observedBranch.Protected,
	}, nil
}

// baselineGET never accepts a user-supplied host: callers construct URLs
// exclusively under the fixed GitHub API origin from canonical selectors.
func (r *PublicIssueReader) baselineGET(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, ErrInvalidGoal
	}
	if req.URL.Scheme != "https" || req.URL.Host != "api.github.com" || req.URL.User != nil || req.URL.RawQuery != "" {
		return nil, ErrInvalidGoal
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "acp-issue-goal/0.1")
	r.addReadAuthorization(req)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, newPublicSourceFailure(ErrBaselineSourceUnavailable, "baseline", "transport", 0)
	}
	defer resp.Body.Close()
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK {
		return nil, newPublicSourceFailure(ErrBaselineSourceUnavailable, "baseline", "http_status", resp.StatusCode)
	}
	if err != nil || (media != "application/json" && media != "application/vnd.github+json") {
		return nil, newPublicSourceFailure(ErrBaselineSourceUnavailable, "baseline", "invalid_media", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBaselineResponseBytes+1))
	if err != nil || len(raw) > maxBaselineResponseBytes || rejectCaseFoldKeyCollisions(raw) != nil {
		return nil, newPublicSourceFailure(ErrBaselineSourceUnavailable, "baseline", "invalid_body", resp.StatusCode)
	}
	return raw, nil
}
