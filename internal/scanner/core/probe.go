package core

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/fingerprint"
)

// DefaultFingerprint is the TLS ClientHello profile every scanner subpackage
// uses unless a caller overrides it. The zero value (Default) means "use Go's
// stock hello". The CLI sets it via scanner.SetFingerprint -- for example
// --tls-fingerprint chrome_133 -- so the scanner presents a browser hello.
var DefaultFingerprint fingerprint.Profile

// SetFingerprint changes the default TLS ClientHello profile for all scanners
// built through NewHTTPClient / SendProbe. It is safe to call before any scan
// starts; it is not safe to call concurrently with in-flight probes.
func SetFingerprint(p fingerprint.Profile) {
	DefaultFingerprint = p
}

// SendProbe sends a single HTTP request and returns the response.
// It is used by all scanner subpackages (tls, waf, http, security).
func SendProbe(target, method, path string, headers http.Header) (*http.Response, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	u.Path = path

	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, err
	}

	if headers != nil {
		for k, vs := range headers {
			for _, v := range vs {
				req.Header.Set(k, v)
			}
		}
	}
	ApplyHeaders(req, DefaultFingerprint)

	client := NewHTTPClient(DefaultFingerprint, 10*time.Second, false)

	return client.Do(req)
}

// Requester is the safety-gated seam for all scanner network I/O.
//
// Why this lives in core: a vulnerability scanner that can dial the network
// directly is a scanner whose safety policy can be bypassed by accident. Every
// check family (passive headers, injection, intrusive) is written against the
// Requester interface instead of *http.Client, and the only production
// implementation is Guard (guard.go), which enforces:
//
//   - an explicit scope allowlist (fail-closed: no list means no probe),
//   - an opt-in gate for intrusive probes (off by default),
//   - a total request budget and a per-host rate limit,
//   - a per-request timeout and a response size cap,
//   - an identifiable User-Agent,
//   - a dry-run mode that answers every policy question without sending bytes.
//
// Probes are also deliberately written so they can be unit-tested against an
// in-memory fake Requester, with no sockets involved.
type Requester interface {
	// Check applies policy (scope allowlist, intrusive gate, budget, dry-run)
	// WITHOUT sending anything. It is the only correct way to ask "am I allowed
	// to try this?" before a probe is built.
	Check(ctx context.Context, method, rawURL string, intrusive bool) error

	// Do sends the request through the rate limiter, budget, timeout, body cap
	// and User-Agent policy. Redirects are never followed: several checks need
	// the raw 3xx and its Location header.
	Do(req *http.Request) (*http.Response, error)
}

// Sentinel errors. Each policy refusal returns exactly one of these (wrapped is
// fine, the sentinel must be matchable with errors.Is), so callers can report
// precisely why a probe did not run instead of guessing.
var (
	ErrOutOfScope        = errors.New("target is outside the authorized scope")
	ErrBudgetExhausted   = errors.New("scanner request budget exhausted")
	ErrRateLimited       = errors.New("per-host rate limit exceeded")
	ErrIntrusiveDisabled = errors.New("intrusive probe disabled (explicit opt-in required)")
	ErrDryRun            = errors.New("dry-run: request not sent")
)

// ScannerUserAgent identifies every probe this tool sends. WSTG expects the
// tester to be identifiable, and an operator of the scanned system can grep
// their access log for this string.
const ScannerUserAgent = "stress-strike-scanner/1.0 (+https://github.com/asadbekabdulboqiyev/stress-strike; authorized-assessment)"

// DefaultProbeLimit is the default response read cap: 2 MiB is enough for
// headers, HTML, JSON and error pages, and small enough that a scanner cannot
// be tricked into downloading a disk image.
const DefaultProbeLimit = 2 << 20

// ReadBody reads at most limit bytes from r and always closes the body.
//
// A limit <= 0 means DefaultProbeLimit. Truncation is silent by design: checks
// only need the head of a response, and a truncated read must never be mistaken
// for a complete one, so callers compare len(body) against the limit when that
// distinction matters.
func ReadBody(r *http.Response, limit int64) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, nil
	}
	defer func() { _ = r.Body.Close() }()
	if limit <= 0 {
		limit = DefaultProbeLimit
	}
	return io.ReadAll(io.LimitReader(r.Body, limit))
}
