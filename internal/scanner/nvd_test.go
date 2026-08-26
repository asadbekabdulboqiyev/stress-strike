package scanner

// Tests for the NVD live integration. Everything runs against a local
// httptest fake NVD server - the real API is never contacted.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- fixtures (realistic NVD API 2.0 shapes) ---------------------------

const nvdItemA = `{"cve":{"id":"CVE-2021-41773","descriptions":[` +
	`{"lang":"en","value":"A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49."},` +
	`{"lang":"es","value":"Se encontro un defecto en Apache HTTP Server."}],` +
	`"metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary",` +
	`"cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8,"baseSeverity":"CRITICAL"}}]},` +
	`"weaknesses":[{"description":[{"lang":"en","value":"CWE-22"}]}],` +
	`"published":"2021-10-05T00:00:00Z","lastModified":"2021-11-16T00:00:00Z",` +
	`"references":[{"url":"https://httpd.apache.org/security/vulnerabilities_24.html"},` +
	`{"url":"https://www.cve.org/CVERecord?id=CVE-2021-41773"}],` +
	`"configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[` +
	`{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*","matchCriteriaId":"AA1"}]}]}]}}`

const nvdItemB = `{"cve":{"id":"CVE-2014-0226","descriptions":[` +
	`{"lang":"en","value":"Race condition in mod_status in Apache HTTP Server 2.4.x allows remote attackers to cause a denial of service."}],` +
	`"metrics":{"cvssMetricV30":[{"source":"nvd@nist.gov","type":"Primary",` +
	`"cvssData":{"version":"3.0","vectorString":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","baseScore":6.8,"baseSeverity":"MEDIUM"}}]},` +
	`"published":"2014-07-20T00:00:00Z","lastModified":"2014-07-22T00:00:00Z",` +
	`"references":[{"url":"https://example.com/advisory-0226"}],` +
	`"configurations":[{"nodes":[{"operator":"OR","cpeMatch":[` +
	`{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.9:*:*:*:*:*:*:*"}]}]}]}}`

const nvdItemC = `{"cve":{"id":"CVE-2023-0000","descriptions":[` +
	`{"lang":"en","value":"Unspecified issue in a web server component with no metrics published yet."}],` +
	`"published":"2023-01-01T00:00:00Z"}}`

func fakeNVDResponse(start, rpp, total int, items ...string) string {
	return fmt.Sprintf(`{"resultsPerPage":%d,"startIndex":%d,"totalResults":%d,"vulnerabilities":[%s]}`,
		rpp, start, total, strings.Join(items, ","))
}

// countingHandler is the fake NVD server: counts every request and can be
// switched between "full" (single full page) and "pages" (paginated) modes.
type countingHandler struct {
	mu      sync.Mutex
	count   int
	mode    string
	queries []url.Values
	headers []http.Header
}

func (h *countingHandler) requests() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

func (h *countingHandler) record(r *http.Request) {
	v := r.URL.Query()
	h.queries = append(h.queries, v)
	h.headers = append(h.headers, r.Header.Clone())
}

func (h *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.count++
	h.record(r)
	mode := h.mode
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	switch mode {
	case "pages":
		if r.URL.Query().Get("startIndex") == "2" {
			fmt.Fprint(w, fakeNVDResponse(2, 2, 3,
				`{"cve":{"id":"CVE-PAGE-0002","descriptions":[{"lang":"en","value":"dup page two"}]}}`,
				`{"cve":{"id":"CVE-PAGE-0003","descriptions":[{"lang":"en","value":"page two item"}]}}`))
		} else {
			fmt.Fprint(w, fakeNVDResponse(0, 2, 3,
				`{"cve":{"id":"CVE-PAGE-0001","descriptions":[{"lang":"en","value":"page one item"}]}}`,
				`{"cve":{"id":"CVE-PAGE-0002","descriptions":[{"lang":"en","value":"dup page one"}]}}`))
		}
	default:
		fmt.Fprint(w, fakeNVDResponse(0, 3, 3, nvdItemA, nvdItemB, nvdItemC))
	}
}

// newTestNVD wires an NVDService to the fake server with throttling off.
func newTestNVD(t *testing.T, h *countingHandler) (*NVDService, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(h)
	svc := NewNVDService(filepath.Join(t.TempDir(), "nvd-cache"), 5*time.Second)
	svc.BaseURL = ts.URL
	svc.MinInterval = 0 // never stall tests
	return svc, ts
}

func cacheKeyForQuery(q string) string {
	return "kw_" + sanitizeNVDKey(q)
}

// seedCache writes a cache entry with a backdated fetched_at.
func seedCache(t *testing.T, dir, query string, age time.Duration, results []NVDCVE) string {
	t.Helper()
	path := filepath.Join(dir, "nvd_"+cacheKeyForQuery(query)+".json")
	entry := nvdCacheEntry{FetchedAt: time.Now().Add(-age), Query: query, Results: results}
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal cache entry: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir cache dir: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write cache file: %v", err)
	}
	return path
}

// ---- tests ---------------------------------------------------------------

func TestNVDScoreToSeverity(t *testing.T) {
	cases := map[float64]string{
		10.0: "critical", 9.8: "critical", 9.0: "critical",
		8.9: "high", 7.5: "high", 7.0: "high",
		6.9: "medium", 4.0: "medium",
		3.9: "low", 0.0: "low",
	}
	for score, want := range cases {
		if got := scoreToSeverity(score); got != want {
			t.Errorf("scoreToSeverity(%v) = %q, want %q", score, got, want)
		}
	}
}

func TestNVDSanitizeKey(t *testing.T) {
	for _, in := range []string{"../../etc/passwd", "a/b\\c", "..", "", "HTTP Server 2.4.49"} {
		got := sanitizeNVDKey(in)
		if strings.ContainsAny(got, "/\\") || strings.Contains(got, "..") {
			t.Errorf("sanitizeNVDKey(%q) = %q: unsafe path fragment", in, got)
		}
		if len(got) > 80 {
			t.Errorf("sanitizeNVDKey(%q): too long (%d)", in, len(got))
		}
	}
	long := sanitizeNVDKey(strings.Repeat("x/", 100))
	if len(long) != 80 {
		t.Errorf("sanitizeNVDKey long input length = %d, want 80", len(long))
	}
}

func TestNVDSearchParseFilter(t *testing.T) {
	h := &countingHandler{}
	svc, ts := newTestNVD(t, h)
	defer ts.Close()

	res := svc.Search("http_server", "2.4.49")
	if len(res) != 3 {
		t.Fatalf("got %d results, want 3 (incl. config-less CVE kept): %+v", len(res), res)
	}

	byID := map[string]NVDCVE{}
	for _, c := range res {
		byID[c.ID] = c
	}

	a := byID["CVE-2021-41773"]
	if a.Severity != "critical" || a.CVSS != 9.8 {
		t.Errorf("CVE-2021-41773 severity/cvss = %q/%v, want critical/9.8", a.Severity, a.CVSS)
	}
	if a.CWE != "CWE-22" {
		t.Errorf("CVE-2021-41773 CWE = %q, want CWE-22", a.CWE)
	}
	if a.VersionHint != "2.4.49" {
		t.Errorf("CVE-2021-41773 version hint = %q, want 2.4.49", a.VersionHint)
	}
	if a.Product != "http_server" {
		t.Errorf("CVE-2021-41773 product = %q, want http_server", a.Product)
	}
	if a.Published.Year() != 2021 || a.LastModified.IsZero() {
		t.Errorf("CVE-2021-41773 times = %v / %v", a.Published, a.LastModified)
	}
	if len(a.References) != 2 {
		t.Errorf("CVE-2021-41773 references = %d, want 2", len(a.References))
	}
	if !strings.HasPrefix(a.Description, "A flaw was found") {
		t.Errorf("CVE-2021-41773 description should be the English one, got: %q", a.Description)
	}

	b := byID["CVE-2014-0226"]
	if b.Severity != "medium" || b.CVSS != 6.8 {
		t.Errorf("CVE-2014-0226 severity/cvss = %q/%v, want medium/6.8 (V3.0 fallback)", b.Severity, b.CVSS)
	}

	c := byID["CVE-2023-0000"]
	if c.Severity != "" || c.CVSS != 0 {
		t.Errorf("CVE-2023-0000 severity/cvss = %q/%v, want empty/0 (no metrics)", c.Severity, c.CVSS)
	}
}

func TestNVDCacheHitNoExtraRequests(t *testing.T) {
	h := &countingHandler{}
	svc, ts := newTestNVD(t, h)
	defer ts.Close()

	first := svc.Search("http_server", "2.4.49")
	n1 := h.requests() // includes the one-time reachability probe

	second := svc.Search("http_server", "2.4.49")
	if got := h.requests(); got != n1 {
		t.Fatalf("second Search issued %d new request(s), want 0 (cache hit)", got-n1)
	}
	if len(first) != len(second) {
		t.Fatalf("cached result size changed: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Errorf("cached result[%d] ID mismatch: %s vs %s", i, first[i].ID, second[i].ID)
		}
	}
	if _, err := os.Stat(filepath.Join(svc.cacheDir, "nvd_"+cacheKeyForQuery("http_server 2.4.49")+".json")); err != nil {
		t.Errorf("expected cache file on disk: %v", err)
	}
}

func TestNVDCacheTTLExpiryRefetches(t *testing.T) {
	h := &countingHandler{}
	dir := filepath.Join(t.TempDir(), "cache")
	ts := httptest.NewServer(h)
	defer ts.Close()

	marker := NVDCVE{ID: "CVE-STALE-MARKER", Description: "stale cached entry", Severity: "low"}
	seedCache(t, dir, "http_server 2.4.49", 25*time.Hour, []NVDCVE{marker}) // TTL is 24h

	svc := NewNVDService(dir, 5*time.Second)
	svc.BaseURL = ts.URL
	svc.MinInterval = 0

	before := h.requests()
	res := svc.Search("http_server", "2.4.49")

	if got := h.requests(); got <= before {
		t.Fatalf("expired cache was not refetched (requests before=%d after=%d)", before, got)
	}
	for _, c := range res {
		if c.ID == marker.ID {
			t.Errorf("stale marker CVE survived refetch: %+v", c)
		}
	}
	if len(res) != 3 {
		t.Errorf("refetched results = %d, want 3", len(res))
	}
}

func TestNVDCorruptCacheIgnoredAndRefetched(t *testing.T) {
	h := &countingHandler{}
	dir := filepath.Join(t.TempDir(), "cache")
	ts := httptest.NewServer(h)
	defer ts.Close()

	path := seedCache(t, dir, "http_server 2.4.49", time.Hour, nil)
	if err := os.WriteFile(path, []byte("{corrupt json!!!"), 0o600); err != nil {
		t.Fatalf("corrupt cache file: %v", err)
	}

	svc := NewNVDService(dir, 5*time.Second)
	svc.BaseURL = ts.URL
	svc.MinInterval = 0

	before := h.requests()
	res := svc.Search("http_server", "2.4.49")
	if len(res) != 3 {
		t.Fatalf("results after corrupt cache = %d, want 3", len(res))
	}
	if got := h.requests(); got <= before {
		t.Errorf("corrupt cache was not ignored/refetched (before=%d after=%d)", before, got)
	}
}

func TestNVDOfflineFallsBackToCacheOrEmpty(t *testing.T) {
	// Dead endpoint: grab a URL then close the server.
	dead := httptest.NewServer(&countingHandler{})
	url := dead.URL
	dead.Close()

	dir := filepath.Join(t.TempDir(), "cache")
	stale := NVDCVE{ID: "CVE-STALE-OFFLINE", Description: "stale but served offline"}
	seedCache(t, dir, "nginx 1.18", 48*time.Hour, []NVDCVE{stale})

	svc := NewNVDService(dir, 2*time.Second)
	svc.BaseURL = url // unreachable
	svc.MinInterval = 0

	if svc.Available() {
		t.Fatal("Available() = true for unreachable BaseURL")
	}

	// Cache exists -> stale entries are returned even though expired.
	got := svc.Search("nginx", "1.18")
	if len(got) != 1 || got[0].ID != stale.ID {
		t.Errorf("offline Search with cache = %+v, want [CVE-STALE-OFFLINE]", got)
	}

	// No cache -> empty slice, no panic.
	empty := svc.Search("openssh", "9.0")
	if empty == nil || len(empty) != 0 {
		t.Errorf("offline Search without cache = %v, want non-nil empty slice", empty)
	}
}

func TestNVDThrottleZeroDoesNotStall(t *testing.T) {
	h := &countingHandler{}
	svc, ts := newTestNVD(t, h)
	defer ts.Close()

	start := time.Now()
	for _, p := range []string{"http_server", "nginx", "lighttpd"} {
		svc.Search(p, "")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("three searches with MinInterval=0 took %v, must not stall", elapsed)
	}
}

func TestNVDThrottleEnforcesMinInterval(t *testing.T) {
	h := &countingHandler{}
	svc, ts := newTestNVD(t, h)
	defer ts.Close()
	svc.MinInterval = 400 * time.Millisecond

	start := time.Now()
	svc.Search("http_server", "") // first live call: no wait
	svc.Search("nginx", "")       // second live call: must wait >= interval
	elapsed := time.Since(start)

	if elapsed < 350*time.Millisecond {
		t.Errorf("two live calls took %v; MinInterval=400ms was not enforced", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("throttle overshot: %v", elapsed)
	}
}

func TestNVDPaginationDedupesAcrossPages(t *testing.T) {
	h := &countingHandler{mode: "pages"}
	svc, ts := newTestNVD(t, h)
	defer ts.Close()

	res := svc.Search("anyprod", "1.0")
	if h.requests() < 2 {
		t.Errorf("expected paginated fetch (>=2 page requests), got %d", h.requests())
	}
	if len(res) != 3 {
		t.Fatalf("deduped results = %d (%+v), want 3 unique IDs", len(res), res)
	}
	seen := map[string]bool{}
	for _, c := range res {
		if seen[c.ID] {
			t.Errorf("duplicate ID across pages: %s", c.ID)
		}
		seen[c.ID] = true
	}
	for _, id := range []string{"CVE-PAGE-0001", "CVE-PAGE-0002", "CVE-PAGE-0003"} {
		if !seen[id] {
			t.Errorf("missing expected ID %s", id)
		}
	}
}

func TestNVDSearchCPESendsParam(t *testing.T) {
	h := &countingHandler{}
	svc, ts := newTestNVD(t, h)
	defer ts.Close()

	cpe := "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
	res := svc.SearchCPE(cpe)
	if len(res) == 0 {
		t.Fatal("SearchCPE returned no results")
	}
	found := false
	for _, q := range h.queries {
		if q.Get("cpeName") == cpe {
			found = true
		}
	}
	if !found {
		t.Errorf("cpeName param missing from requests: %v", h.queries)
	}
	// Product token is derived from the CPE for configured entries.
	var sawProduct bool
	for _, c := range res {
		if c.Product == "http_server" {
			sawProduct = true
		}
	}
	if !sawProduct {
		t.Errorf(`no result carried product "http_server": %+v`, res)
	}
}

func TestNVDApiKeyHeaderAndUserAgent(t *testing.T) {
	h := &countingHandler{}
	svc, ts := newTestNVD(t, h)
	defer ts.Close()
	svc.ApiKey = "sk-test-secret-123"

	svc.Search("http_server", "")

	if len(h.headers) == 0 {
		t.Fatal("no requests recorded")
	}
	var sawKey, sawUA bool
	for _, hd := range h.headers {
		if hd.Get("apiKey") == "sk-test-secret-123" {
			sawKey = true
		}
		if hd.Get("User-Agent") == "stress-strike/1.0" {
			sawUA = true
		}
	}
	if !sawKey {
		t.Error("apiKey header not sent when ApiKey set")
	}
	if !sawUA {
		t.Error(`User-Agent header is not "stress-strike/1.0"`)
	}
}
