package browser

// Headless browser (Chromium/CDP) integration for Sift scanner.
//
// USE:
//   - JavaScript-rendered (SPA / React / Vue / Angular) page endpoints and
//     form discovery (crawler)
//   - OAuth / deep login flow execution in browser (auth)
//   - Black-box scanning of dynamic JavaScript logical buttons (login,
//     checkout, payment, admin panel) on JS-rendered pages
//
// Chrome/Chromium must be installed on the system (macOS: Google Chrome or
// Chromium; Linux: google-chrome-stable / chromium-browser).

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// Browser is a simple wrapper around headless Chromium.
type Browser struct {
	opts []chromedp.ExecAllocatorOption
	mu   sync.Mutex
}

// New creates a browser instance. Returns an error if Chrome/Chromium is not
// installed or cannot start.
func New() (*Browser, error) {
	opts := append([]chromedp.ExecAllocatorOption{},
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", "new"),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.UserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"),
	)
	b := &Browser{opts: opts}

	// Check that Chrome/Chromium is available. The probe must run on the
	// chromedp context, not on the plain timeout context: chromedp.Run looks up
	// the allocated browser in the context it is given, and passing the timeout
	// context made every call fail with "invalid context" — which is how this
	// package silently became unusable.
	timeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), probeTimeout())
	defer cancelTimeout()

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(timeoutCtx, opts...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	if _, err := chromedp.Run(browserCtx, chromedp.Navigate("about:blank")); err != nil {
		return nil, fmt.Errorf("browser: chromium not found or failed to start: %w (install Google Chrome / Chromium)", err)
	}
	return b, nil
}

// probeTimeout is how long New() waits for the browser to come up.
//
// It is a variable so a slow or loaded machine can extend it: browser launch on
// a shared CI runner under the race detector has been observed to exceed the
// default, and a first launch with a cold disk cache is slower still. The
// default is what an interactive machine needs.
var probeTimeout = func() time.Duration { return 30 * time.Second }

// ctx creates a browser context (separate for each request).
//
// The caller's cancel tears down the whole chain — timeout, browser session and
// allocator. The previous version deferred cancelAlloc() *inside* ctx, so the
// allocator was cancelled the moment ctx returned, i.e. before the caller had
// used the context at all.
func (b *Browser) ctx(timeout time.Duration) (context.Context, context.CancelFunc) {
	b.mu.Lock()
	opts := append([]chromedp.ExecAllocatorOption(nil), b.opts...)
	b.mu.Unlock()

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	ctx, cancelTimeout := context.WithTimeout(browserCtx, timeout)

	return ctx, func() {
		cancelTimeout()
		cancelBrowser()
		cancelAlloc()
	}
}

// Page opens a URL, fully executes JS, and returns the rendered HTML.
func (b *Browser) Page(targetURL string, timeout time.Duration) (string, error) {
	ctx, cancel := b.ctx(timeout)
	defer cancel()

	// Navigate + wait + sleep (all void actions)
	if err := chromedp.Do(ctx,
		chromedp.Navigate(targetURL),
		chromedp.WaitReady(chromedp.CSS("body")),
		chromedp.Sleep(1500*time.Millisecond), // wait for JS rendering
	); err != nil {
		return "", fmt.Errorf("browser: failed to open page %s: %w", targetURL, err)
	}

	// Extract HTML (Action[string])
	html, err := chromedp.Run(ctx, chromedp.OuterHTML(chromedp.CSS("html")))
	if err != nil {
		return "", fmt.Errorf("browser: error getting HTML %s: %w", targetURL, err)
	}
	return html, nil
}

// Endpoint is extracted from HTML: <a href> and <form action> tags.
type Endpoint struct {
	URL     string   `json:"url"`
	Method  string   `json:"method"` // GET | POST
	Params  []string `json:"params"`
	FoundAt string   `json:"found_at"`
	Kind    string   `json:"kind"` // link | form
}

// ExtractEndpoints extracts all endpoints from the HTML rendered in browser.
// This is important for React/Vue/Angular JS-generated pages.
//
// Two things this must get right, because the crawler feeds the result straight
// into the intrusion path:
//
//   - a form's parameters are the inputs inside *that* form. The previous
//     version scanned the whole document for <input name>, so with two forms on
//     a page each one inherited the other's fields — a login form was reported
//     with the search form's parameters, and the injected POST was wrong.
//   - the dedup key includes the method. A /search link and a GET form for the
//     same URL are one endpoint, but a /transfer link and a POST form for the
//     same URL are two: dropping the POST lost the state-changing endpoint.
func ExtractEndpoints(html, baseURL string) []Endpoint {
	var eps []Endpoint
	seen := make(map[string]bool)

	base, err := url.Parse(baseURL)
	if err != nil {
		return eps
	}

	add := func(method, kind, rawURL, foundAt string, params []string) {
		if rawURL == "" {
			return
		}
		lower := strings.ToLower(rawURL)
		for _, bad := range []string{"mailto:", "tel:", "javascript:", "data:"} {
			if strings.HasPrefix(lower, bad) {
				return
			}
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			return
		}
		abs := base.ResolveReference(u).String()
		key := method + " " + abs
		if seen[key] {
			return
		}
		seen[key] = true
		eps = append(eps, Endpoint{
			URL:     abs,
			Method:  method,
			Params:  params,
			FoundAt: foundAt,
			Kind:    kind,
		})
	}

	// <a href="...">
	reHref := regexp.MustCompile(`<a\s+[^>]*href\s*=\s*["']([^"']+)["']`)
	for _, m := range reHref.FindAllStringSubmatch(html, -1) {
		add("GET", "link", m[1], baseURL, nil)
	}

	// <form ...> with its own inputs.
	reFormOpen := regexp.MustCompile(`(?is)<form\b[^>]*>`)
	reFormClose := regexp.MustCompile(`(?is)</form\s*>`)
	reInputName := regexp.MustCompile(`(?is)<input\b[^>]*\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)

	for _, loc := range reFormOpen.FindAllStringIndex(html, -1) {
		openTag := html[loc[0]:loc[1]]
		attrs := parseTagAttrs(openTag)

		bodyStart := loc[1]
		bodyEnd := len(html)
		// The form ends at the earlier of its closing tag and the next form's
		// opening tag. Without the second bound, an unterminated form swallowed
		// the next form's inputs and reported them as its own parameters.
		if closeLoc := reFormClose.FindStringIndex(html[bodyStart:]); closeLoc != nil {
			bodyEnd = bodyStart + closeLoc[0]
		}
		if nextOpen := reFormOpen.FindStringIndex(html[bodyStart:]); nextOpen != nil {
			if next := bodyStart + nextOpen[0]; next < bodyEnd {
				bodyEnd = next
			}
		}
		inner := html[bodyStart:bodyEnd]

		var params []string
		for _, im := range reInputName.FindAllStringSubmatch(inner, -1) {
			name := im[1] + im[2] + im[3]
			if name != "" {
				params = append(params, name)
			}
		}

		method := strings.ToUpper(strings.TrimSpace(attrs["method"]))
		if method == "" {
			method = "GET"
		}
		add(method, "form", attrs["action"], baseURL, params)
	}

	return eps
}

// parseTagAttrs returns the attribute values of one opening tag. Names are
// lower-cased. Quoted and unquoted values are both accepted, and a value-less
// attribute (required, multiple) maps to "".
func parseTagAttrs(tag string) map[string]string {
	attrs := make(map[string]string)
	reAttr := regexp.MustCompile(`(?is)([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?`)
	for _, m := range reAttr.FindAllStringSubmatch(tag, -1) {
		name := strings.ToLower(m[1])
		if name == "form" || strings.HasPrefix(name, "<") {
			continue
		}
		if _, exists := attrs[name]; exists {
			continue
		}
		attrs[name] = m[2] + m[3] + m[4]
	}
	return attrs
}

// LoginForm fills in a login form in browser and submits it (OAuth / deep auth).
// usernameSel / passwordSel — full CSS selectors (e.g. input[name='username']).
func (b *Browser) LoginForm(loginURL, usernameSel, passwordSel, username, password string, extraFields map[string]string, successMatch string, timeout time.Duration) (bool, string, error) {
	ctx, cancel := b.ctx(timeout)
	defer cancel()

	// Navigate + wait + sleep + sendkeys (all void actions)
	actions := []chromedp.Action[chromedp.Void]{
		chromedp.Navigate(loginURL),
		chromedp.WaitReady(chromedp.CSS("body")),
		chromedp.Sleep(1000 * time.Millisecond),
	}

	// Enter username (usernameSel is already a full CSS selector)
	actions = append(actions,
		chromedp.SendKeys(chromedp.CSS(usernameSel), username),
	)

	// Enter password (passwordSel is already a full CSS selector)
	actions = append(actions,
		chromedp.SendKeys(chromedp.CSS(passwordSel), password),
	)

	// Extra fields (CSRF token etc.)
	for k, v := range extraFields {
		actions = append(actions,
			chromedp.SendKeys(chromedp.CSS(`[name="`+k+`"]`), v),
		)
	}

	// Submit form (press Enter)
	actions = append(actions,
		chromedp.SendKeys(chromedp.CSS(passwordSel), "\n"),
		chromedp.WaitReady(chromedp.CSS("body")),
		chromedp.Sleep(2000*time.Millisecond),
	)

	if err := chromedp.Do(ctx, actions...); err != nil {
		return false, "", fmt.Errorf("browser: login failed %s: %w", loginURL, err)
	}

	// Re-read the page (Action[string])
	var finalBody string
	finalBody, err := chromedp.Run(ctx, chromedp.OuterHTML(chromedp.CSS("body")))
	if err != nil {
		return false, "", fmt.Errorf("browser: error reading response: %w", err)
	}

	return loginSucceeded(finalBody, successMatch), finalBody, nil
}

// loginSucceeded decides whether a submitted login flow actually authenticated.
//
// An explicit successMatch is a substring the operator knows proves a session
// ("Sign out", the account name). Without one the only evidence available is
// that the page no longer looks like a login page — that heuristic is stated
// here, in one place, instead of being buried in the middle of a browser
// action chain.
func loginSucceeded(finalBody, successMatch string) bool {
	if successMatch != "" {
		return strings.Contains(finalBody, successMatch)
	}
	lower := strings.ToLower(finalBody)
	return !strings.Contains(lower, "login") &&
		!strings.Contains(lower, "sign in") &&
		!strings.Contains(lower, "password")
}

// EnsureAvailable checks that the browser is available.
func EnsureAvailable() error {
	_, err := New()
	return err
}
