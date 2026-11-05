// Package browserload provides browser-based load testing using a real
// Chromium-based browser via chromedp. This lets stress-strike measure how a
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
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/runtime"
)

// RunResult describes a single browser page-load measurement.
type RunResult struct {
	URL          string        `json:"url"`
	LoadTime     time.Duration `json:"load_time"`     // navigationStart → loadEventEnd
	DOMContent   time.Duration `json:"dom_content"`   // navigationStart → domContentLoadedEventEnd
	StatusCode   int           `json:"status_code"`
	Error        string        `json:"error,omitempty"`
	JSErrors     []string      `json:"js_errors"`     // console errors captured during load
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

// Run loads url in a headless browser and returns performance timings. The
// context must be cancellable; Run respects ctx.Done().
func (r *Runner) Run(ctx context.Context, urlStr string) (*RunResult, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
		urlStr = u.String()
	}

	ctx, cancel := chromedp.NewContext(
		context.Background(),
		chromedp.WithLogf(func(fmt string, args ...interface{}) {}),
	)
	defer cancel()

	// Set a timeout wrapper so a hung page doesn't block forever.
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	result := &RunResult{URL: urlStr}

	var jsErrors []string
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			if ev.Type == "error" {
				for _, a := range ev.Args {
					jsErrors = append(jsErrors, string(a.Value))
				}
			}
		case *runtime.EventExceptionThrown:
			jsErrors = append(jsErrors, fmt.Sprintf("exception: %v", ev.ExceptionDetails.Text))
		}
	})

	var navStart, loadEnd, domEnd float64
	err = chromedp.Run(ctx,
		chromedp.Navigate(urlStr),
		chromedp.Evaluate(`performance.timing.navigationStart`, &navStart),
		chromedp.Evaluate(`performance.timing.loadEventEnd`, &loadEnd),
		chromedp.Evaluate(`performance.timing.domContentLoadedEventEnd`, &domEnd),
	)
	if err != nil {
		result.Error = err.Error()
		result.JSErrors = jsErrors
		return result, err
	}

	result.LoadTime = time.Duration(loadEnd-navStart) * time.Millisecond
	result.DOMContent = time.Duration(domEnd-navStart) * time.Millisecond
	result.JSErrors = jsErrors

	// Attempt to read the HTTP status code via fetch (may not always work
	// depending on page/cors).
	var status int
	_ = chromedp.Evaluate(`fetch(window.location.href).then(r=>r.status).catch(()=>0)`, &status).Do(ctx)
	result.StatusCode = status

	return result, nil
}

// RunConcurrent runs n concurrent page loads against url. Results are returned
// in completion order. Use this for light browser load testing (e.g. 5-20
// concurrent tabs); for larger loads, use the HTTP engine instead.
func (r *Runner) RunConcurrent(ctx context.Context, url string, n int) ([]*RunResult, error) {
	results := make([]*RunResult, n)
	errCh := make(chan error, n)

	for i := 0; i < n; i++ {
		go func(i int) {
			res, err := r.Run(ctx, url)
			results[i] = res
			errCh <- err
		}(i)
	}

	for i := 0; i < n; i++ {
		if err := <-errCh; err != nil {
			return results, err
		}
	}
	return results, nil
}
