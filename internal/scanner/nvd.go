package scanner

// NVD live integration: queries the free NVD API 2.0 (services.nvd.nist.gov)
// to unlock 240K+ CVEs beyond the static signatures in cve.go.
//
// Design notes:
//   - stdlib only, defensive parsing (every field optional).
//   - File-based JSON cache with a 24h TTL; corrupt cache files are ignored.
//   - Simple mutex throttle: ~5 req/30s without an API key (12s min interval),
//     ~100 req/30s with one (0.6s min interval). Interval is settable so
//     tests can disable it.
//   - Offline safety: any network error falls back to cache (even stale) or
//     an empty slice. Never panics. The API key is never logged.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	nvdDefaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdUserAgent      = "stress-strike/1.0"
	nvdAPIKeyHeader   = "apiKey"
	nvdPageSize       = 2000            // API maximum resultsPerPage
	nvdMaxPages       = 5               // hard cap: 10K CVEs per search
	nvdCacheTTL       = 24 * time.Hour  // fresh-cache window
	nvdMaxBodyBytes   = 64 << 20        // 64 MiB response cap
)

// NVDCVE is a single vulnerability returned by the live NVD service.
type NVDCVE struct {
	ID           string    `json:"id"`                     // CVE-2024-1234
	Description  string    `json:"description"`
	Severity     string    `json:"severity"`               // critical/high/medium/low (derived from CVSS)
	CVSS         float64   `json:"cvss"`                   // v3.1 base score preferred
	CWE          string    `json:"cwe,omitempty"`
	Published    time.Time `json:"published"`
	LastModified time.Time `json:"last_modified,omitempty"`
	References   []string  `json:"references,omitempty"`
	Product      string    `json:"product"`                // matched product name
	VersionHint  string    `json:"version_hint,omitempty"` // version expression matched, e.g. "< 2.4.51"
}

// nvdCacheEntry is the on-disk cache envelope.
type nvdCacheEntry struct {
	FetchedAt time.Time `json:"fetched_at"` // TTL anchor
	Query     string    `json:"query"`
	Results   []NVDCVE  `json:"results"`
}

// NVDService talks to the NVD API 2.0 with caching and rate limiting.
// BaseURL, ApiKey and MinInterval are exported so the CLI and tests can
// configure them. ApiKey must never be written to logs or errors.
type NVDService struct {
	BaseURL     string        // default https://services.nvd.nist.gov/rest/json/cves/2.0
	ApiKey      string        // optional; sent as "apiKey" header, never logged
	MinInterval time.Duration // min gap between live calls; <0 = auto (12s, or 0.6s with key); tests use 0

	cacheDir string
	client   *http.Client

	mu       sync.Mutex
	lastCall time.Time // last live API call time (shared across Search calls)

	availMu      sync.Mutex
	availChecked bool
	available    bool
}

// NewNVDService creates a service. Empty cacheDir falls back to a directory
// under os.TempDir(); timeout <= 0 defaults to 20s.
func NewNVDService(cacheDir string, timeout time.Duration) *NVDService {
	if cacheDir == "" {
		cacheDir = filepath.Join(os.TempDir(), "stress-strike-nvd")
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &NVDService{
		BaseURL:     nvdDefaultBaseURL,
		MinInterval: -1, // auto mode
		cacheDir:    cacheDir,
		client:      &http.Client{Timeout: timeout},
	}
}

// Available performs a cheap reachability probe once per process lifetime
// and caches the result. It returns false on any network error.
func (n *NVDService) Available() bool {
	n.availMu.Lock()
	defer n.availMu.Unlock()
	if n.availChecked {
		return n.available
	}
	n.availChecked = true
	n.available = false

	u, err := url.Parse(n.BaseURL)
	if err != nil {
		return false
	}
	q := u.Query()
	q.Set("resultsPerPage", "1")
	u.RawQuery = q.Encode()

	timeout := 5 * time.Second
	if n.client.Timeout > 0 && n.client.Timeout < timeout {
		timeout = n.client.Timeout
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", nvdUserAgent)
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	// 4xx still means the endpoint is reachable (e.g. rate limited).
	n.available = resp.StatusCode >= 200 && resp.StatusCode < 500
	return n.available
}

// Search runs a keyword search for "product version" against NVD, following
// pagination up to the hard page cap and deduplicating by CVE ID.
func (n *NVDService) Search(product, version string) []NVDCVE {
	product = strings.TrimSpace(product)
	version = strings.TrimSpace(version)
	parts := make([]string, 0, 2)
	if product != "" {
		parts = append(parts, product)
	}
	if version != "" {
		parts = append(parts, version)
	}
	query := strings.Join(parts, " ")
	if query == "" {
		return []NVDCVE{}
	}
	key := "kw_" + sanitizeNVDKey(query)
	if !n.Available() {
		return n.cacheFallback(key) // offline: cache-only results
	}
	vals := url.Values{}
	vals.Set("keywordSearch", query)
	return n.fetchQuery(vals, key, strings.ToLower(product), product)
}

// SearchCPE searches CVEs matching an exact CPE name, e.g.
// cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*.
func (n *NVDService) SearchCPE(cpeName string) []NVDCVE {
	cpeName = strings.TrimSpace(cpeName)
	if cpeName == "" {
		return []NVDCVE{}
	}
	key := "cpe_" + sanitizeNVDKey(cpeName)
	if !n.Available() {
		return n.cacheFallback(key)
	}
	vals := url.Values{}
	vals.Set("cpeName", cpeName)
	product := ""
	// Best-effort product token from the CPE (part 5 of the colon-split).
	if p := strings.Split(cpeName, ":"); len(p) > 4 {
		product = p[4]
	}
	return n.fetchQuery(vals, key, "", product)
}

// fetchQuery loads a fresh cache entry if possible; otherwise it pages
// through the live API. On any error it returns cached (even stale) data
// or an empty slice.
func (n *NVDService) fetchQuery(vals url.Values, cacheKey, keyword, product string) []NVDCVE {
	if e, ok := n.loadCache(cacheKey, true); ok {
		return e.Results
	}
	seen := map[string]bool{}
	out := []NVDCVE{}
	start := 0
	for page := 0; page < nvdMaxPages; page++ {
		vals.Set("startIndex", strconv.Itoa(start))
		vals.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
		env, err := n.get(vals)
		if err != nil {
			return n.cacheFallback(cacheKey)
		}
		for _, item := range env.Vulnerabilities {
			cve, keep := convertItem(item.CVE, keyword, product)
			if keep && cve != nil && !seen[cve.ID] {
				seen[cve.ID] = true
				out = append(out, *cve)
			}
		}
		got := len(env.Vulnerabilities)
		start += got
		if got <= 0 || got < env.ResultsPerPage || (env.TotalResults > 0 && start >= env.TotalResults) {
			break
		}
	}
	n.saveCache(cacheKey, out)
	return out
}

// get performs one throttled GET against the API and decodes the envelope.
func (n *NVDService) get(vals url.Values) (*nvdEnvelope, error) {
	n.throttle()
	u, err := url.Parse(n.BaseURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for k, vs := range vals {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", nvdUserAgent)
	if n.ApiKey != "" {
		req.Header.Set(nvdAPIKeyHeader, n.ApiKey)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("nvd: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, nvdMaxBodyBytes))
	if err != nil {
		return nil, err
	}
	var env nvdEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// throttle enforces the minimum interval between live API calls. The lock is
// held while sleeping so concurrent Search callers are serialized on one
// shared schedule.
func (n *NVDService) throttle() {
	n.mu.Lock()
	defer n.mu.Unlock()
	interval := n.effectiveInterval()
	if interval > 0 && !n.lastCall.IsZero() {
		if wait := interval - time.Since(n.lastCall); wait > 0 {
			time.Sleep(wait)
		}
	}
	n.lastCall = time.Now()
}

// effectiveInterval resolves the throttle delay: explicit MinInterval wins;
// otherwise 0.6s with an API key, 12s without one.
func (n *NVDService) effectiveInterval() time.Duration {
	if n.MinInterval >= 0 {
		return n.MinInterval
	}
	if n.ApiKey != "" {
		return 600 * time.Millisecond
	}
	return 12 * time.Second
}

// cacheFallback returns cached data ignoring TTL; empty slice when absent.
func (n *NVDService) cacheFallback(key string) []NVDCVE {
	if e, ok := n.loadCache(key, false); ok {
		return e.Results
	}
	return []NVDCVE{}
}

func (n *NVDService) cachePath(key string) string {
	return filepath.Join(n.cacheDir, "nvd_"+key+".json")
}

// loadCache reads a cache entry. requireFresh enforces the 24h TTL;
// unreadable or corrupt files are treated as a miss.
func (n *NVDService) loadCache(key string, requireFresh bool) (*nvdCacheEntry, bool) {
	b, err := os.ReadFile(n.cachePath(key))
	if err != nil {
		return nil, false
	}
	var e nvdCacheEntry
	if err := json.Unmarshal(b, &e); err != nil || e.FetchedAt.IsZero() {
		return nil, false // corrupt -> ignore and refetch
	}
	if requireFresh && time.Since(e.FetchedAt) > nvdCacheTTL {
		return nil, false // expired
	}
	return &e, true
}

// saveCache persists results atomically enough for our purposes; write
// failures are silently ignored (cache is best-effort).
func (n *NVDService) saveCache(key string, results []NVDCVE) {
	if results == nil {
		results = []NVDCVE{}
	}
	e := nvdCacheEntry{FetchedAt: time.Now(), Results: results}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	_ = os.MkdirAll(n.cacheDir, 0o700)
	_ = os.WriteFile(n.cachePath(key), b, 0o600)
}

// sanitizeNVDKey maps arbitrary search text onto a safe filename fragment:
// lowercase alphanumerics plus -_. kept, everything else collapsed to '_',
// capped at 80 bytes so no slashes or traversal tricks survive.
func sanitizeNVDKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	for strings.Contains(out, "..") {
		out = strings.ReplaceAll(out, "..", ".") // no traversal sequences
	}
	if len(out) > 80 {
		out = out[:80]
	}
	if out == "" || out == "." {
		out = "empty"
	}
	return out
}

// ---- response parsing -------------------------------------------------

// nvdEnvelope mirrors the top-level NVD API 2.0 JSON shape.
type nvdEnvelope struct {
	ResultsPerPage int             `json:"resultsPerPage"`
	StartIndex     int             `json:"startIndex"`
	TotalResults   int             `json:"totalResults"`
	Vulnerabilities []rawItemWrap `json:"vulnerabilities"`
}

type rawItemWrap struct {
	CVE rawCVE `json:"cve"`
}

type rawMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

type rawDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type rawCPEMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Criteria   string `json:"criteria"`
}

type rawNode struct {
	Operator string        `json:"operator"`
	CPEMatch []rawCPEMatch `json:"cpeMatch"`
}

type rawConfiguration struct {
	Nodes []rawNode `json:"nodes"`
}

type rawCVE struct {
	ID           string            `json:"id"`
	Descriptions []rawDescription  `json:"descriptions"`
	Metrics      struct {
		CvssMetricV31 []rawMetric `json:"cvssMetricV31"`
		CvssMetricV30 []rawMetric `json:"cvssMetricV30"`
		CvssMetricV2  []rawMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []rawDescription `json:"description"`
	} `json:"weaknesses"`
	Published      string            `json:"published"`
	LastModified   string            `json:"lastModified"`
	References     []struct {
		URL string `json:"url"`
	} `json:"references"`
	Configurations []rawConfiguration `json:"configurations"`
}

// convertItem maps one raw CVE record onto NVDCVE defensively.
// keyword filters by CPE product mention when configurations exist
// (empty keyword keeps everything, used by SearchCPE).
func convertItem(c rawCVE, keyword, product string) (*NVDCVE, bool) {
	out := &NVDCVE{ID: strings.TrimSpace(c.ID), Product: product}

	// First English description, else first available.
	for _, d := range c.Descriptions {
		if d.Lang == "en" && strings.TrimSpace(d.Value) != "" {
			out.Description = d.Value
			break
		}
	}
	if out.Description == "" && len(c.Descriptions) > 0 {
		out.Description = c.Descriptions[0].Value
	}

	// CVSS: prefer v3.1, then v3.0, then v2. Severity derived from score.
	lists := [][]rawMetric{c.Metrics.CvssMetricV31, c.Metrics.CvssMetricV30, c.Metrics.CvssMetricV2}
	for _, list := range lists {
		if len(list) > 0 {
			score := list[0].CVSSData.BaseScore
			out.CVSS = score
			out.Severity = scoreToSeverity(score)
			break
		}
	}

	// First CWE-* weakness identifier.
loopWeak:
	for _, wk := range c.Weaknesses {
		for _, d := range wk.Description {
			v := strings.TrimSpace(d.Value)
			if strings.HasPrefix(v, "CWE-") {
				out.CWE = v
				break loopWeak
			}
		}
	}

	out.Published = parseNVDTime(c.Published)
	out.LastModified = parseNVDTime(c.LastModified)

	for _, r := range c.References {
		if u := strings.TrimSpace(r.URL); u != "" {
			out.References = append(out.References, u)
		}
	}

	// Product filter: when configurations exist and a keyword was given,
	// require at least one CPE criteria mentioning it (case-insensitive);
	// capture a version hint from the matched criteria. Entries without
	// configurations are always kept.
	if len(c.Configurations) > 0 {
		matched := false
		for _, conf := range c.Configurations {
			for _, node := range conf.Nodes {
				for _, cm := range node.CPEMatch {
					crit := strings.ToLower(cm.Criteria)
					if keyword == "" || strings.Contains(crit, keyword) {
						matched = true
						if out.VersionHint == "" {
							if v := cpeVersion(cm.Criteria); v != "*" && v != "" {
								out.VersionHint = v
							}
						}
					}
				}
			}
		}
		if keyword != "" && !matched {
			return nil, false
		}
	}
	return out, true
}

// scoreToSeverity maps a CVSS base score to a severity bucket.
func scoreToSeverity(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	default:
		return "low"
	}
}

// cpeVersion extracts the version segment (index 5) from a CPE 2.3 URI.
func cpeVersion(criteria string) string {
	parts := strings.Split(criteria, ":")
	if len(parts) > 5 {
		return parts[5]
	}
	return ""
}

// parseNVDTime tolerates the several timestamp shapes NVD emits
// (with/without fractional seconds, with/without timezone).
func parseNVDTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
