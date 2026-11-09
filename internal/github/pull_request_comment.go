// Package github provides GitHub API helpers for the stress-strike project.
//
// It uses the GITHUB_TOKEN (provided by the CI environment) to post
// rich-markdown comments on pull requests and issues. No external API keys
// are required — the token is injected by GitHub Actions automatically.
//
// Supported operations:
//   - PostComment   : add a comment to an issue or PR
//   - ListComments  : list existing comments
//   - UpdateComment : update an existing comment (by ID)
//
// The comment body is treated as Markdown. Rich formatting (tables, code
// blocks, @mentions, checkboxes) is preserved as-is.
package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// --- Data types ------------------------------------------------------------

// Comment represents a GitHub issue/PR comment.
type Comment struct {
	ID      int64  `json:"id"`
	URL     string `json:"url"`
	HTMLURL string `json:"html_url"`
	Body    string `json:"body"`
	User    struct {
		Login string `json:"login"`
	} `json:"user"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ReactionEvent represents a reaction added to a comment.
type ReactionEvent struct {
	Event   string `json:"event"`
	Subject struct {
		URL string `json:"url"`
	} `json:"subject"`
}

// CreateCommentInput is the payload for posting a new comment.
type CreateCommentInput struct {
	Body string `json:"body"` // Markdown body; HTML is auto-converted by GitHub
}

// --- GitHub API endpoints --------------------------------------------------

// APIBase is the base URL for the GitHub REST API v3.
const APIBase = "https://api.github.com"

// doRequest performs a single GET/POST/PATCH/DELETE request and returns the
// response body. It handles basic auth (token in Authorization header) and
// returns an error if the HTTP status is not 2xx.
func doRequest(method, endpoint string, body io.Reader) ([]byte, int, error) {
	u, _ := url.Parse(APIBase + endpoint)
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, 0, fmt.Errorf("github: new %s request: %w", method, err)
	}
	// GitHub Actions injects the token as the GITHUB_ENV variable, but the
	// HTTP header is the standard way:
	req.Header.Set("Authorization", "token "+getToken())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("github: do %s %s: %w", method, endpoint, err)
	}
	defer resp.Body.Close()
	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("github: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resBody, resp.StatusCode, nil
	}
	return resBody, resp.StatusCode, nil
}

// getToken reads the GITHUB_TOKEN from the environment. In GitHub Actions
// this is automatically available; in local dev it must be set.
func getToken() string {
	t := os.Getenv("GITHUB_TOKEN")
	if strings.TrimSpace(t) != "" {
		return strings.TrimSpace(t)
	}
	return ""
}

// --- Public API ------------------------------------------------------------

// PostComment adds a rich-markdown comment to the given issue or pull request.
//
//	owner/repo   e.g. "adsr/strike"
//	issueNumber  the PR or issue number (not the GitHub API internal ID)
//	body         Markdown text; GitHub renders it natively.
//
// Returns the newly created comment's ID, or an error.
func PostComment(ownerRepo string, issueNumber int, body string) (int64, error) {
	input := CreateCommentInput{Body: body}
	issuePath := "/repos/" + ownerRepo + "/issues/" + fmt.Sprintf("%d", issueNumber) + "/comments"
	b, statusCode, err := doRequest("POST", issuePath, bytes.NewReader(mustJSON(input)))
	if err != nil {
		return 0, fmt.Errorf("github: post comment to %s#%d: %w", ownerRepo, issueNumber, err)
	}
	if statusCode < 200 || statusCode >= 300 {
		return 0, fmt.Errorf("github: server returned %d: %s", statusCode, string(b))
	}
	var comment Comment
	if err := json.Unmarshal(b, &comment); err != nil {
		return 0, fmt.Errorf("github: parse comment response: %w", err)
	}
	return comment.ID, nil
}

// ListComments returns all comments on an issue or pull request.
//
//	owner/repo   e.g. "adsr/strike"
//	issueNumber  the PR or issue number
//
// Returns a slice of Comment, or an error.
func ListComments(ownerRepo string, issueNumber int) ([]Comment, error) {
	issuePath := "/repos/" + ownerRepo + "/issues/" + fmt.Sprintf("%d", issueNumber) + "/comments"
	b, statusCode, err := doRequest("GET", issuePath, nil)
	if err != nil {
		return nil, fmt.Errorf("github: list comments for %s#%d: %w", ownerRepo, issueNumber, err)
	}
	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("github: server returned %d: %s", statusCode, string(b))
	}
	var comments []Comment
	if err := json.Unmarshal(b, &comments); err != nil {
		return nil, fmt.Errorf("github: parse comments list: %w", err)
	}
	return comments, nil
}

// UpdateComment replaces the body of an existing comment.
//
//	commentID    the GitHub-assigned comment ID
//	body         new Markdown body
//
// Returns true on success, or an error.
func UpdateComment(commentID int64, body string) error {
	issuePath := "/repos/" + fmt.Sprintf("%d", commentID) + "/comments"
	b, statusCode, err := doRequest("PATCH", issuePath, bytes.NewReader(mustJSON(CreateCommentInput{Body: body})))
	if err != nil {
		return fmt.Errorf("github: update comment %d: %w", commentID, err)
	}
	if statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("github: server returned %d: %s", statusCode, string(b))
	}
	return nil
}

// mustJSON marshals v to JSON or panics. Used for test/simplification code.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("json marshal failure: %v", err))
	}
	return b
}

// --- Rich-Markdown template helper ----------------------------------------

// RichReport returns a markdown-formatted report suitable for posting as a
// GitHub PR comment. It includes tables, code blocks, and status badges.
//
// The report is intentionally self-contained so it can be copied verbatim
// into a GitHub comment without external dependencies.
func RichReport(title, status string, metrics map[string]int, findings []string) string {
	// Build a simple table of metrics.
	var rows []string
	for k, v := range metrics {
		rows = append(rows, fmt.Sprintf("| %s | %d |", k, v))
	}
	table := ""
	if len(rows) > 0 {
		table = "| Metric | Count |\n|--------|-------|\n" + strings.Join(rows, "\n") + "\n"
	}

	// Build a findings list (bulleted).
	var findingsHTML []string
	for _, f := range findings {
		findingsHTML = append(findingsHTML, fmt.Sprintf("- %s", f))
	}
	foundations := ""
	if len(findingsHTML) > 0 {
		foundations = "* Findings:\n" + strings.Join(findingsHTML, "\n")
	}

	return fmt.Sprintf(`**stress-strike Security Assessment**

**%s**

**Status:** %s

%s

%s

*Generated by stress-strike dashboard / CI integration.*
`, title, status, table, foundations)
}
