package github

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestServer points apiBase at an httptest server and restores it after the
// test. It also swaps in a short-timeout client so a hanging handler fails
// rather than stalling the suite.
func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	oldBase, oldClient := apiBase, httpClient
	apiBase = srv.URL
	httpClient = &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(func() {
		apiBase, httpClient = oldBase, oldClient
		srv.Close()
	})
	return srv
}

func TestPostCommentSendsAuthenticatedRequest(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "  secret-token  ")

	var (
		gotMethod string
		gotPath   string
		gotAuth   string
		gotAccept string
		gotVer    string
		gotCT     string
		gotBody   map[string]string
	)

	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotVer = r.Header.Get("X-GitHub-Api-Version")
		gotCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":4242,"html_url":"https://example/1"}`))
	})

	id, err := PostComment("adsr/strike", 7, "## report")
	if err != nil {
		t.Fatalf("PostComment: %v", err)
	}
	if id != 4242 {
		t.Fatalf("id = %d, want 4242", id)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/repos/adsr/strike/issues/7/comments" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "token secret-token" {
		t.Errorf("Authorization = %q, want token trimming applied", gotAuth)
	}
	if gotAccept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", gotAccept)
	}
	if gotVer != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version = %q", gotVer)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if gotBody["body"] != "## report" {
		t.Errorf("body = %q", gotBody["body"])
	}
}

func TestPostCommentServerError(t *testing.T) {
	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
	})

	_, err := PostComment("adsr/strike", 7, "x")
	if err == nil {
		t.Fatal("expected error for 403")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "not accessible") {
		t.Fatalf("error = %v, want status and body", err)
	}
}

func TestPostCommentBadJSONResponse(t *testing.T) {
	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>oops</html>`))
	})

	if _, err := PostComment("adsr/strike", 7, "x"); err == nil {
		t.Fatal("expected parse error")
	} else if !strings.Contains(err.Error(), "parse comment response") {
		t.Fatalf("error = %v", err)
	}
}

func TestListComments(t *testing.T) {
	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/repos/adsr/strike/issues/9/comments" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[
			{"id":1,"body":"first","user":{"login":"bot"},"html_url":"u1"},
			{"id":2,"body":"second","user":{"login":"dev"}}
		]`))
	})

	comments, err := ListComments("adsr/strike", 9)
	if err != nil {
		t.Fatalf("ListComments: %v", err)
	}
	if len(comments) != 2 {
		t.Fatalf("len = %d, want 2", len(comments))
	}
	if comments[0].ID != 1 || comments[0].Body != "first" || comments[0].User.Login != "bot" || comments[0].HTMLURL != "u1" {
		t.Errorf("comment[0] = %+v", comments[0])
	}
	if comments[1].ID != 2 || comments[1].User.Login != "dev" {
		t.Errorf("comment[1] = %+v", comments[1])
	}
}

func TestListCommentsServerError(t *testing.T) {
	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	})

	if _, err := ListComments("adsr/strike", 9); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v, want 500", err)
	}
}

func TestUpdateCommentUsesRepoScopedPatchEndpoint(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotBody   map[string]string
	)
	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":999}`))
	})

	if err := UpdateComment("adsr/strike", 999, "updated body"); err != nil {
		t.Fatalf("UpdateComment: %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("method = %q, want PATCH", gotMethod)
	}
	// GitHub's real endpoint: PATCH /repos/{owner}/{repo}/issues/comments/{id}
	if gotPath != "/repos/adsr/strike/issues/comments/999" {
		t.Errorf("path = %q, want repo-scoped comment endpoint", gotPath)
	}
	if gotBody["body"] != "updated body" {
		t.Errorf("body = %q", gotBody["body"])
	}
}

func TestUpdateCommentServerError(t *testing.T) {
	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	})

	err := UpdateComment("adsr/strike", 1, "x")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error = %v, want 404", err)
	}
}

func TestDoRequestNetworkFailure(t *testing.T) {
	oldBase, oldClient := apiBase, httpClient
	// Reserved-for-documentation address that nothing listens on: connection
	// is refused immediately instead of hanging.
	apiBase = "http://127.0.0.1:1"
	httpClient = &http.Client{Timeout: 2 * time.Second}
	t.Cleanup(func() { apiBase, httpClient = oldBase, oldClient })

	if err := UpdateComment("adsr/strike", 1, "x"); err == nil {
		t.Fatal("expected network error")
	} else if !strings.Contains(err.Error(), "github:") {
		t.Fatalf("error = %v, want github prefix", err)
	}
}

func TestDoRequestInvalidBaseURL(t *testing.T) {
	oldBase := apiBase
	apiBase = "://missing-scheme"
	t.Cleanup(func() { apiBase = oldBase })

	_, _, err := doRequest(http.MethodGet, "/x", nil)
	if err == nil || !strings.Contains(err.Error(), "parse url") {
		t.Fatalf("error = %v, want parse url error", err)
	}
}

func TestRichReportWithMetricsAndFindings(t *testing.T) {
	got := RichReport("Nightly fuzz", "FAIL", map[string]int{"crashes": 3}, []string{"heap overflow"})

	for _, want := range []string{
		"Sift Security Assessment",
		"**Nightly fuzz**",
		"**Status:** FAIL",
		"| Metric | Count |",
		"| crashes | 3 |",
		"* Findings:",
		"- heap overflow",
		"*Generated by Sift",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report missing %q\n%s", want, got)
		}
	}
}

func TestRichReportWithoutOptionalSections(t *testing.T) {
	got := RichReport("Smoke", "PASS", nil, nil)

	if strings.Contains(got, "| Metric |") {
		t.Errorf("unexpected metrics table:\n%s", got)
	}
	if strings.Contains(got, "* Findings:") {
		t.Errorf("unexpected findings section:\n%s", got)
	}
	if !strings.Contains(got, "**Status:** PASS") {
		t.Errorf("missing status line:\n%s", got)
	}
}

func TestGetToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "  abc123  ")
	if got := getToken(); got != "abc123" {
		t.Fatalf("getToken = %q, want trimmed token", got)
	}

	t.Setenv("GITHUB_TOKEN", "   ")
	if got := getToken(); got != "" {
		t.Fatalf("getToken = %q, want empty for whitespace-only token", got)
	}
}

func TestAPIBaseConstant(t *testing.T) {
	if APIBase != "https://api.github.com" {
		t.Fatalf("APIBase = %q", APIBase)
	}
	if apiBase != APIBase {
		t.Fatalf("apiBase default = %q, want APIBase", apiBase)
	}
}
