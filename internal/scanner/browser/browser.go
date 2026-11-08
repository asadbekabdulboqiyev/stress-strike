package browser

// Headless browser (Chromium/CDP) integration for stress-strike scanner.
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

	// Check that Chrome/Chromium is available
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()
	allocCtx, cancel = chromedp.NewContext(allocCtx)
	defer cancel()
	if _, err := chromedp.Run(ctx, chromedp.Navigate("about:blank")); err != nil {
		return nil, fmt.Errorf("browser: chromium not found or failed to start: %w (install Google Chrome / Chromium)", err)
	}
	return b, nil
}

// ctx creates a browser context (separate for each request).
func (b *Browser) ctx(timeout time.Duration) (context.Context, context.CancelFunc) {
	b.mu.Lock()
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), b.opts...)
	defer cancelAlloc()
	b.mu.Unlock()
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	ctx, cancel = context.WithTimeout(ctx, timeout)
	return ctx, cancel
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
func ExtractEndpoints(html, baseURL string) []Endpoint {
	var eps []Endpoint
	seen := make(map[string]bool)

	add := func(method, kind, rawURL, foundAt string, params []string) {
		if rawURL == "" {
			return
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			return
		}
		base, err := url.Parse(baseURL)
		if err != nil {
			return
		}
		abs := base.ResolveReference(u).String()
		if seen[abs] {
			return
		}
		seen[abs] = true
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

	// <form action="..." method="POST/GET">
	reForm := regexp.MustCompile(`(?i)<form\s+[^>]*action\s*=\s*["']([^"']+)["'][^>]*method\s*=\s*["']([^"']+)["']`)
	for _, m := range reForm.FindAllStringSubmatch(html, -1) {
		action := m[1]
		method := strings.ToUpper(m[2])
		if method == "" {
			method = "GET"
		}
		// Extract input names
		var params []string
		reInput := regexp.MustCompile(`<input\s+[^>]*name\s*=\s*["']([^"']+)["']`)
		for _, im := range reInput.FindAllStringSubmatch(html, -1) {
			params = append(params, im[1])
		}
		add(method, "form", action, baseURL, params)
	}

	return eps
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
		chromedp.Sleep(2000 * time.Millisecond),
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

	// Check success match
	success := false
	if successMatch != "" {
		success = strings.Contains(finalBody, successMatch)
	} else {
		// Default: success if navigated away from login page
		success = !strings.Contains(strings.ToLower(finalBody), "login") &&
			!strings.Contains(strings.ToLower(finalBody), "sign in") &&
			!strings.Contains(strings.ToLower(finalBody), "password")
	}

	return success, finalBody, nil
}

// EnsureAvailable checks that the browser is available.
func EnsureAvailable() error {
	_, err := New()
	return err
}
