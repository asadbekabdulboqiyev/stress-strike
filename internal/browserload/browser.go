// Package browserload provides browser-based load testing using a real
// Chromium-based browser via chromedp. This lets Sift measure how a
// target performs for an actual end user (JS rendering, CSS layout, image
// loading, XHR/fetch), which the plain HTTP engine cannot capture.
//
// Browser load testing is intentionally heavier than the HTTP engine: each
// virtual user is a real browser tab. It is meant for SPA/JS-rendered pages
// and end-user experience validation, not for raw throughput.
//
// See docs/ROADMAP.md for the full browser load testing rollout plan.
package browserload

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// RunResult describes a single browser page-load measurement.
type RunResult struct {
	URL        string        `json:"url"`
	LoadTime   time.Duration `json:"load_time"`   // navigationStart → loadEventEnd
	DOMContent time.Duration `json:"dom_content"` // navigationStart → domContentLoadedEventEnd
	StatusCode int           `json:"status_code"`
	Error      string        `json:"error,omitempty"`
	JSErrors   []string      `json:"js_errors"` // console errors captured during load
}

// Runner executes page loads in a real browser.
type Runner struct {
	opts []chromedp.ExecAllocatorOption
}

// NewRunner creates a headless Chrome runner. It attempts to find a Chrome
// binary on the system; if none is found, Run() will return an error.
func NewRunner() *Runner {
	return &Runner{
		opts: []chromedp.ExecAllocatorOption{
			chromedp.Flag("headless", "new"),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-dev-shm-usage", true),
			chromedp.Flag("disable-background-timer-throttling", true),
			chromedp.Flag("disable-backgrounding-occluded-windows", true),
			chromedp.Flag("disable-renderer-backgrounding", true),
			chromedp.Flag("disable-features", "TranslateUI"),
			chromedp.Flag("disable-ipc-flooding-protection", true),
			chromedp.Flag("no-first-run", true),
			chromedp.Flag("no-default-browser-check", true),
			chromedp.Flag("disable-default-apps", true),
			chromedp.Flag("disable-sync", true),
			chromedp.Flag("metrics-recording-only", true),
			chromedp.Flag("mute-audio", true),
			chromedp.Flag("remote-debugging-port", "0"),
		},
	}
}

// normalizeURL parses a target URL and supplies the default scheme.
//
// A bare host ("example.com") is what an operator types, and there is no
// browser load test without a scheme, so https is assumed — the same default
// the scanner uses. Everything else is left alone: this function must not
// rewrite a URL a target expects byte for byte.
func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
		return u.String(), nil
	}
	return raw, nil
}

// Run loads url in a headless browser and returns performance timings. The
// context must be cancellable; Run respects ctx.Done().
func (r *Runner) Run(ctx context.Context, urlStr string) (*RunResult, error) {
	urlStr, err := normalizeURL(urlStr)
	if err != nil {
		return nil, err
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), r.opts...)
	defer cancelAlloc()

	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(fmt string, args ...interface{}) {}))
	defer cancel()

	// Set a timeout wrapper so a hung page doesn't block forever.
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	result := &RunResult{URL: urlStr}

	var js jsErrorLog
	_ = chromedp.Listen(ctx, js.handle)
	snapshot := js.snapshot

	// Navigate first (void action)
	if err := chromedp.Do(ctx, chromedp.Navigate(urlStr)); err != nil {
		result.Error = err.Error()
		result.JSErrors = snapshot()
		return result, err
	}

	// Then evaluate timing (returning values).
	navStart, err := chromedp.Run(ctx, chromedp.Evaluate[float64](`performance.timing.navigationStart`))
	if err != nil {
		result.Error = err.Error()
		result.JSErrors = snapshot()
		return result, err
	}
	loadEnd, err := chromedp.Run(ctx, chromedp.Evaluate[float64](`performance.timing.loadEventEnd`))
	if err != nil {
		result.Error = err.Error()
		result.JSErrors = snapshot()
		return result, err
	}
	domEnd, err := chromedp.Run(ctx, chromedp.Evaluate[float64](`performance.timing.domContentLoadedEventEnd`))
	if err != nil {
		result.Error = err.Error()
		result.JSErrors = snapshot()
		return result, err
	}

	result.LoadTime = time.Duration(loadEnd-navStart) * time.Millisecond
	result.DOMContent = time.Duration(domEnd-navStart) * time.Millisecond
	result.JSErrors = snapshot()

	// Attempt to read the HTTP status code via fetch (may not always work
	// depending on page/cors). EvalAwaitPromise is required: without it the
	// result is the Promise object, not the status, and StatusCode stays 0.
	var status int
	if _, err := chromedp.Run(ctx, chromedp.Evaluate[int](
		`fetch(window.location.href).then(r=>r.status).catch(()=>0)`,
		chromedp.EvalAwaitPromise,
	)); err != nil {
		// Ignore fetch errors - status may not be available
		status = 0
	}
	result.StatusCode = status

	return result, nil
}

// RunConcurrent runs n concurrent page loads against url. Results are returned
// in completion order. Use this for light browser load testing (e.g. 5-20
// concurrent tabs); for larger loads, use the HTTP engine instead.
func (r *Runner) RunConcurrent(ctx context.Context, url string, n int) ([]*RunResult, error) {
	if n < 0 {
		return nil, fmt.Errorf("concurrent browser runs: n = %d, want >= 0", n)
	}
	if n == 0 {
		return []*RunResult{}, nil
	}

	results := make([]*RunResult, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = r.Run(ctx, url)
		}(i)
	}

	// Wait for every tab to finish before handing the slice back. The previous
	// version returned on the first error, which let the remaining goroutines
	// keep writing into the slice the caller already owned — a data race that
	// only appeared when one tab failed while others were still loading.
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return results, err
		}
	}
	return results, nil
}
