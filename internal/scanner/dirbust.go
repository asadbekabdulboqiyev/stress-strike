package scanner

// --- Directory brute-forcer --------------------------------------------------
//
// Discovers hidden files/directories on a web server by guessing common
// paths. Every request goes through the Requester gate so scope/rate/budget
// are enforced. Returns paths that respond with non-404 status codes.

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DirBustResult is the output of a directory brute-force run.
type DirBustResult struct {
	Target   string        `json:"target"`
	Found    int           `json:"found"`
	Entries  []DirEntry    `json:"entries,omitempty"`
	Duration time.Duration `json:"duration"`
}

// DirEntry is one discovered path.
type DirEntry struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	Size       int    `json:"size"`
	Title      string `json:"title,omitempty"`
}

// commonPaths is a curated wordlist of sensitive/common paths.
var commonPaths = []string{
	"/", "/admin", "/administrator", "/wp-admin", "/wp-login.php",
	"/.env", "/.git/", "/.svn/", "/.hg/", "/.bzr/",
	"/config.php", "/configuration.php", "/settings.py",
	"/.htaccess", "/.htpasswd", "/web.config",
	"/phpinfo.php", "/info.php", "/test.php",
	"/api", "/api/v1", "/api/v2", "/graphql", "/graphql/",
	"/swagger", "/swagger.json", "/openapi.json", "/openapi/",
	"/docs", "/documentation", "/redoc",
	"/backup", "/bak", "/old", "/test", "/dev", "/staging",
	"/.well-known/", "/robots.txt", "/sitemap.xml",
	"/.ssh/", "/.aws/", "/.dockerenv", "/Dockerfile",
	"/server-status", "/server-info", "/nginx_status",
	"/manager", "/manager/html", "/host-manager",
	"/console", "/actuator", "/actuator/health",
	"/.idea/", "/.vscode/", "/.DS_Store",
	"/config.json", "/config.yaml", "/config.yml",
	"/secrets", "/credentials", "/passwords",
	"/upload", "/uploads", "/files", "/file",
	"/export", "/import", "/download",
	"/.npm/", "/.composer/", "/vendor/",
	"/node_modules/", "/package.json",
	"/.babelrc", "/.eslintrc", "/.gitignore",
	"/LICENSE", "/README.md", "/CHANGELOG.md",
	"/.git/HEAD", "/.git/config",
	"/wp-content/", "/wp-includes/", "/wp-json/",
	"/.well-known/security.txt",
	"/.well-known/assetlinks.json",
}

// DirBust runs a directory brute-force against base (e.g. https://example.com).
func DirBust(ctx context.Context, base string, paths []string, req Requester) *DirBustResult {
	res := &DirBustResult{Target: base}
	start := time.Now()

	if len(paths) == 0 {
		paths = commonPaths
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 40)

	for _, p := range paths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			u := strings.TrimRight(base, "/") + path
			parsed, err := url.Parse(u)
			if err != nil {
				return
			}
			reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
			if err != nil {
				return
			}
			reqHTTP.Header.Set("User-Agent", "stress-strike-dirbust/1.0")

			if err := req.Check(ctx, http.MethodGet, parsed.String(), false); err != nil {
				return
			}
			resp, err := req.Do(reqHTTP)
			if err != nil {
				return
			}
			defer func() { _ = resp.Body.Close() }()

			// Interesting: anything other than 404/403 (403 may still be interesting
			// but we include it as a discovered path).
			if resp.StatusCode == http.StatusNotFound {
				return
			}

			body, _ := ioReadAllLimit(resp.Body, 4<<20)
			title := extractTitle(string(body))

			mu.Lock()
			res.Found++
			res.Entries = append(res.Entries, DirEntry{
				URL:        parsed.String(),
				Method:     http.MethodGet,
				StatusCode: resp.StatusCode,
				Size:       len(body),
				Title:      title,
			})
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	res.Duration = time.Since(start)
	return res
}

func ioReadAllLimit(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}

func extractTitle(html string) string {
	// naive <title> extraction
	start := strings.Index(strings.ToLower(html), "<title>")
	if start < 0 {
		return ""
	}
	start += 7
	end := strings.Index(strings.ToLower(html[start:]), "</title>")
	if end < 0 {
		return strings.TrimSpace(html[start:])
	}
	return strings.TrimSpace(html[start : start+end])
}
