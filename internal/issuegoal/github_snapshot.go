package issuegoal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const IssueSnapshotVersion = "acp.github-issue-snapshot/v1"
const maxPublicIssueResponseBytes = 128 * 1024

var (
	ErrIssueSourceUnavailable = errors.New("GitHub Issue source unavailable")
	ErrIssueSnapshotMismatch  = errors.New("GitHub Issue snapshot digest mismatch")
)

// GitHubIssueSnapshot is observed public Issue content, not a GitHub
// signature, authorization grant, or a durable copy of the source bytes.
type GitHubIssueSnapshot struct {
	Schema    string `json:"schema"`
	IssueURL  string `json:"issue_url"`
	IssueID   int64  `json:"issue_id"`
	Number    int64  `json:"number"`
	State     string `json:"state"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	UpdatedAt string `json:"updated_at"`
	Digest    string `json:"digest"`
}

// Explicit preimage prevents a change to the output DTO from silently
// changing a versioned digest. JSON key order is defined by field order.
type canonicalIssueSnapshotV1 struct {
	Schema    string `json:"schema"`
	IssueURL  string `json:"issue_url"`
	IssueID   int64  `json:"issue_id"`
	Number    int64  `json:"number"`
	State     string `json:"state"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	UpdatedAt string `json:"updated_at"`
}

// PublicIssueReader only sends read-only requests to the fixed api.github.com
// hostname. It has no caller-supplied endpoint, token or redirect allowance.
type PublicIssueReader struct {
	client *http.Client
}

func NewPublicIssueReader() *PublicIssueReader {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &PublicIssueReader{client: &http.Client{
		Timeout:       10 * time.Second,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func ValidateIssueURL(value string) error {
	if !validGitHubIssueURL(value) {
		return ErrInvalidGoal
	}
	return nil
}

// Read observes a public open Issue over GitHub's REST API, rejects pull
// requests and conflicting source IDs, and pins the versioned title/body
// snapshot. Caller-supplied Issue text is never an instruction authority.
func (r *PublicIssueReader) Read(ctx context.Context, issueURL string) (GitHubIssueSnapshot, error) {
	if r == nil || r.client == nil || ValidateIssueURL(issueURL) != nil {
		return GitHubIssueSnapshot{}, ErrInvalidGoal
	}
	parts := strings.Split(issueURL, "/")
	owner, repo, number := parts[3], parts[4], parts[6]
	repoAPI := "https://api.github.com/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repoAPI+"/issues/"+number, nil)
	if err != nil {
		return GitHubIssueSnapshot{}, ErrInvalidGoal
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "acp-issue-goal/0.1")
	resp, err := r.client.Do(req)
	if err != nil {
		return GitHubIssueSnapshot{}, newPublicSourceFailure(ErrIssueSourceUnavailable, "issue", "transport", 0)
	}
	defer resp.Body.Close()
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK {
		return GitHubIssueSnapshot{}, newPublicSourceFailure(ErrIssueSourceUnavailable, "issue", "http_status", resp.StatusCode)
	}
	if err != nil || (media != "application/json" && media != "application/vnd.github+json") {
		return GitHubIssueSnapshot{}, newPublicSourceFailure(ErrIssueSourceUnavailable, "issue", "invalid_media", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPublicIssueResponseBytes+1))
	if err != nil || len(raw) > maxPublicIssueResponseBytes ||
		rejectCaseFoldKeyCollisions(raw) != nil {
		return GitHubIssueSnapshot{}, newPublicSourceFailure(ErrIssueSourceUnavailable, "issue", "invalid_body", resp.StatusCode)
	}
	var observed struct {
		ID            int64           `json:"id"`
		Number        int64           `json:"number"`
		HTMLURL       string          `json:"html_url"`
		RepositoryURL string          `json:"repository_url"`
		Title         string          `json:"title"`
		Body          *string         `json:"body"`
		State         string          `json:"state"`
		UpdatedAt     string          `json:"updated_at"`
		PullRequest   json.RawMessage `json:"pull_request"`
	}
	if json.Unmarshal(raw, &observed) != nil {
		return GitHubIssueSnapshot{}, newPublicSourceFailure(ErrIssueSourceUnavailable, "issue", "invalid_body", resp.StatusCode)
	}
	wantNumber, _ := strconv.ParseInt(number, 10, 64)
	if observed.ID <= 0 || observed.Number != wantNumber ||
		observed.HTMLURL != issueURL || observed.RepositoryURL != repoAPI ||
		observed.Title == "" || len(observed.Title) > 16*1024 ||
		observed.State != "open" || len(observed.PullRequest) != 0 {
		return GitHubIssueSnapshot{}, newPublicSourceFailure(ErrIssueSourceUnavailable, "issue", "invalid_body", resp.StatusCode)
	}
	if _, err := time.Parse(time.RFC3339, observed.UpdatedAt); err != nil {
		return GitHubIssueSnapshot{}, newPublicSourceFailure(ErrIssueSourceUnavailable, "issue", "invalid_body", resp.StatusCode)
	}
	body := ""
	if observed.Body != nil {
		body = *observed.Body
	}
	snapshot := GitHubIssueSnapshot{
		Schema: IssueSnapshotVersion, IssueURL: issueURL, IssueID: observed.ID,
		Number: observed.Number, State: observed.State, Title: observed.Title,
		Body: body, UpdatedAt: observed.UpdatedAt,
	}
	canonical, err := json.Marshal(canonicalIssueSnapshotV1{
		Schema: snapshot.Schema, IssueURL: snapshot.IssueURL,
		IssueID: snapshot.IssueID, Number: snapshot.Number, State: snapshot.State,
		Title: snapshot.Title, Body: snapshot.Body, UpdatedAt: snapshot.UpdatedAt,
	})
	if err != nil {
		return GitHubIssueSnapshot{}, newPublicSourceFailure(ErrIssueSourceUnavailable, "issue", "invalid_body", resp.StatusCode)
	}
	digest := sha256.Sum256(canonical)
	snapshot.Digest = "sha256:" + hex.EncodeToString(digest[:])
	return snapshot, nil
}

// Verify re-fetches the current public Issue and rejects mismatched content.
// It does not check commit SHAs, rule authority, budget or ACLs.
func (r *PublicIssueReader) Verify(ctx context.Context, issueURL, wantedDigest string) error {
	if !strings.HasPrefix(wantedDigest, "sha256:") ||
		!validHex(strings.TrimPrefix(wantedDigest, "sha256:"), 64) {
		return ErrInvalidGoal
	}
	snapshot, err := r.Read(ctx, issueURL)
	if err != nil {
		return err
	}
	if snapshot.Digest != wantedDigest {
		return ErrIssueSnapshotMismatch
	}
	return nil
}
