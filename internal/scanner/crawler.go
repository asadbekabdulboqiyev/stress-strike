package scanner

// crawler.go implements the site-crawling module (spider) for stress-strike.
// It performs a breadth-first crawl of a target web application, discovering
// links and forms, and reports every endpoint found in an authorized
// pentest engagement. Regex-based HTML extraction keeps this iteration
// stdlib-only; it is intentionally lenient with malformed markup.

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// --- Public API -------------------------------------------------------------

// Endpoint is a single discovered attack surface entry (link or form).
type Endpoint struct {
	URL     string   `json:"url"`      // absolute URL
	Method  string   `json:"method"`   // "GET" or "POST"
	Params  []string `json:"params"`   // query param names (GET) / form field names (POST)
	FoundAt string   `json:"found_at"` // parent page where discovered
	Kind    string   `json:"kind"`     // "link" | "form"
}

// CrawlResult aggregates everything one crawl produced.
type CrawlResult struct {
	Endpoints []Endpoint    `json:"endpoints"`
	Pages     int           `json:"pages"`
	Duration  time.Duration `json:"duration"`
}

// CrawlOptions tunes crawler behavior.
//
// SameHostOnly from the contract is exposed as its inverted form
// AllowOffsite so the zero value naturally means "stay on-site"
// (the contract explicitly permits this inversion).
type CrawlOptions struct {
	MaxDepth     int           // default 3 if 0
	MaxPages     int           // default 100 if 0
	Timeout      time.Duration // per-request, default 10s
	AllowOffsite bool          // false (default) = never follow offsite links
	UserAgent    string        // default stress-strike crawler UA
	Concurrency  int           // worker pool size, default 5
}

// Crawler crawls a start URL according to Options. Client may be replaced
// (e.g. with an authenticated session client) any time before Crawl().
type Crawler struct {
	StartURL string
	Options  CrawlOptions
	Client   *http.Client

	queue     []crawlJob
	visited   map[string]bool
	endpoints map[string]Endpoint
	fetched   int
}

type crawlJob struct {
	raw   string
	depth int
}

const (
	defaultMaxDepth = 3
	defaultMaxPages = 100
	defaultTimeout  = 10 * time.Second
	defaultConc     = 5
	defaultUA       = "stress-strike-crawler/1.0"
	maxBodyBytes    = 4 << 20 // 4 MiB cap per page body
)

// NewCrawler builds a crawler for startURL, applying option defaults.
func NewCrawler(startURL string, opts CrawlOptions) *Crawler {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = defaultMaxPages
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConc
	}
	if strings.TrimSpace(opts.UserAgent) == "" {
		opts.UserAgent = defaultUA
	}
	return &Crawler{
		StartURL: strings.TrimSpace(startURL),
		Options:  opts,
		Client:   &http.Client{Timeout: opts.Timeout},
	}
}

// Crawl runs the crawl and always returns a non-nil result. It never panics
// on malformed input; parse errors are silently ignored.
func (c *Crawler) Crawl() *CrawlResult {
	start := time.Now()
	res := &CrawlResult{Endpoints: []Endpoint{}}

	base, err := url.Parse(c.StartURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		res.Duration = elapsedSince(start)
		return res
	}

	if c.Client == nil {
		c.Client = &http.Client{Timeout: c.Options.Timeout}
	}

	c.visited = map[string]bool{}
	c.endpoints = map[string]Endpoint{}
	c.fetched = 0

	seedKey := queueKey(base)
	c.visited[seedKey] = true
	c.queue = []crawlJob{{raw: base.String(), depth: 0}}

	for len(c.queue) > 0 && c.fetched < c.Options.MaxPages {
		budget := c.Options.MaxPages - c.fetched
		n := len(c.queue)
		if n > budget {
			n = budget
		}
		batch := c.queue[:n]
		c.queue = c.queue[n:]

		outcomes := make(chan pageOutcome, len(batch))
		sem := make(chan struct{}, c.Options.Concurrency)
		var wg sync.WaitGroup
		for _, j := range batch {
			wg.Add(1)
			go func(j crawlJob) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				outcomes <- c.processJob(j)
			}(j)
		}
		wg.Wait()
		close(outcomes)

		// Single-goroutine consumption keeps visited/endpoints/queue race-free.
		for out := range outcomes {
			if !out.attempted {
				continue
			}
			c.fetched++
			if !out.parseable {
				continue
			}
			for _, ep := range out.endpoints {
				key := endpointKey(ep.Method, ep.URL, ep.Params)
				if _, ok := c.endpoints[key]; !ok {
					ep.FoundAt = out.pageURL
					c.endpoints[key] = ep
				}
			}
			for _, link := range out.links {
				childDepth := out.depth + 1
				if childDepth > c.Options.MaxDepth {
					continue
				}
				k := queueKey(link.parsed)
				if c.visited[k] {
					continue
				}
				c.visited[k] = true
				c.queue = append(c.queue, crawlJob{raw: link.parsed.String(), depth: childDepth})
			}
		}
	}

	res.Pages = c.fetched
	for _, ep := range c.endpoints {
		res.Endpoints = append(res.Endpoints, ep)
	}
	sort.Slice(res.Endpoints, func(i, j int) bool {
		if res.Endpoints[i].URL != res.Endpoints[j].URL {
			return res.Endpoints[i].URL < res.Endpoints[j].URL
		}
		if res.Endpoints[i].Method != res.Endpoints[j].Method {
			return res.Endpoints[i].Method < res.Endpoints[j].Method
		}
		return strings.Join(res.Endpoints[i].Params, ",") < strings.Join(res.Endpoints[j].Params, ",")
	})
	res.Duration = elapsedSince(start)
	return res
}

// --- Fetching ----------------------------------------------------------------

type pageOutcome struct {
	attempted bool   // got an HTTP response (any status counts as a page)
	parseable bool   // 200 + text/html
	pageURL   string // requested URL (FoundAt parent)
	depth     int
	endpoints []Endpoint
	links     []discoveredLink
}

type discoveredLink struct {
	parsed *url.URL
	params []string
}

func (c *Crawler) processJob(j crawlJob) pageOutcome {
	out := pageOutcome{depth: j.depth, pageURL: j.raw}

	ctx, cancel := context.WithTimeout(context.Background(), c.Options.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.raw, nil)
	if err != nil {
		return out
	}
	req.Header.Set("User-Agent", c.Options.UserAgent)

	resp, err := c.Client.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()

	out.attempted = true
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if readErr != nil && len(body) == 0 {
		return out
	}

	// Only 200 responses are mined for links/forms; other statuses still
	// count toward Pages.
	if resp.StatusCode != http.StatusOK {
		return out
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return out // binary or non-HTML: do not parse, do not enqueue
	}
	out.parseable = true

	htmlText := sanitizeHTML(string(body))
	baseURL, _ := url.Parse(j.raw)

	links := extractPageLinks(htmlText, baseURL, c)
	for _, l := range links {
		// Every discovered <a href> is itself an endpoint; its query-string
		// parameter names become the Params list.
		out.endpoints = append(out.endpoints, Endpoint{
			URL:    l.parsed.String(),
			Method: "GET",
			Params: queryParamNames(l.parsed),
			Kind:   "link",
		})
	}
	out.endpoints = append(out.endpoints, extractFormEndpoints(htmlText, baseURL, !c.Options.AllowOffsite)...)
	out.links = links
	return out
}

// --- Link handling -----------------------------------------------------------

func extractPageLinks(htmlText string, baseURL *url.URL, c *Crawler) []discoveredLink {
	var links []discoveredLink
	seenOnPage := map[string]bool{}
	for _, tag := range rxA.FindAllString(htmlText, -1) {
		href := attrValue(tag, rxHrefName)
		u, ok := resolveTarget(baseURL, href)
		if !ok {
			continue
		}
		if !c.Options.AllowOffsite && !sameHost(u, baseURL) {
			continue // offsite links skipped entirely
		}
		key := u.String()
		if seenOnPage[key] {
			continue
		}
		seenOnPage[key] = true
		links = append(links, discoveredLink{parsed: u, params: queryParamNames(u)})
	}
	return links
}

// resolveTarget normalizes a raw href/action against base: strips fragments,
// rejects mailto:/tel:/javascript:/data: and anything not http(s) with a host.
func resolveTarget(base *url.URL, raw string) (*url.URL, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	lower := strings.ToLower(raw)
	for _, bad := range []string{"mailto:", "tel:", "javascript:", "data:"} {
		if strings.HasPrefix(lower, bad) {
			return nil, false
		}
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return nil, false
	}
	u := base.ResolveReference(ref)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, false
	}
	if u.Host == "" {
		return nil, false
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u, true
}

func sameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Host, b.Host)
}

// queueKey collapses a URL to scheme://host/path so query-string variants of
// the same path are fetched only once (prevents combinatorial explosion).
// An empty path is normalized to "/" so http://host and http://host/ merge.
func queueKey(u *url.URL) string {
	return u.Scheme + "://" + strings.ToLower(u.Host) + normalizedPath(u)
}

func normalizedPath(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

func queryParamNames(u *url.URL) []string {
	q := u.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// --- Form handling -----------------------------------------------------------

type formInfo struct {
	action string
	method string
	fields []string
}

// extractFormEndpoints turns <form> regions into POST/GET endpoints.
// When sameHostOnly is true, forms targeting offsite actions are skipped —
// a hostile page must not be able to point the scanner's attack probes at
// third-party hosts.
func extractFormEndpoints(htmlText string, baseURL *url.URL, sameHostOnly bool) []Endpoint {
	var endpoints []Endpoint
	opens := rxFormOpen.FindAllStringIndex(htmlText, -1)
	for i, span := range opens {
		tagEnd := span[1]

		// Form body ends at the first </form>, the next <form, or EOF —
		// unclosed tags must not swallow the rest of the document.
		end := len(htmlText)
		if m := rxFormClose.FindStringIndex(htmlText[tagEnd:]); m != nil {
			end = tagEnd + m[0]
		}
		if i+1 < len(opens) && opens[i+1][0] < end {
			end = opens[i+1][0]
		}
		body := htmlText[tagEnd:end]
		openTag := htmlText[span[0]:tagEnd]

		actionRaw := attrValue(openTag, rxActionName)
		target := baseURL
		if actionRaw != "" {
			if resolved, ok := resolveTarget(baseURL, actionRaw); ok {
				target = resolved
			}
		}
		if sameHostOnly && !sameHost(target, baseURL) {
			continue
		}

		fi := formInfo{
			method: normalizeFormMethod(attrValue(openTag, rxMethodName)),
			fields: formFieldNames(body),
		}
		params := append([]string{}, fi.fields...)
		sort.Strings(params)
		endpoints = append(endpoints, Endpoint{
			URL:    target.String(),
			Method: fi.method,
			Params: params,
			Kind:   "form",
		})
	}
	return endpoints
}

// normalizeFormMethod maps empty/nonstandard methods to POST, GET to GET.
func normalizeFormMethod(m string) string {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "GET":
		return "GET"
	default:
		return "POST"
	}
}

// formFieldNames collects name attributes of input/select/textarea tags.
func formFieldNames(formBody string) []string {
	var names []string
	seen := map[string]bool{}
	for _, tag := range rxFormField.FindAllString(formBody, -1) {
		name := attrValue(tag, rxNameAttr)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

// --- Endpoint keys -----------------------------------------------------------

// endpointKey dedupes by method + normalized path + sorted params (host is
// included so cross-origin collisions can never merge unrelated endpoints).
func endpointKey(method, rawURL string, params []string) string {
	path := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		path = u.Scheme + "://" + strings.ToLower(u.Host) + p
	}
	sorted := append([]string{}, params...)
	sort.Strings(sorted)
	return method + "|" + path + "|" + strings.Join(sorted, "\x1f")
}

func elapsedSince(t time.Time) time.Duration {
	d := time.Since(t)
	if d <= 0 {
		return time.Nanosecond // monotonic guarantee for Duration > 0 checks
	}
	return d
}

// --- Minimal regex HTML extraction ------------------------------------------
// RE2 has no backreferences, so script/style are stripped separately.

var (
	rxComments   = regexp.MustCompile(`(?is)<!--.*?-->`)
	rxScript     = regexp.MustCompile(`(?is)<script\b.*?(?:</script\s*>|\z)`)
	rxStyle      = regexp.MustCompile(`(?is)<style\b.*?(?:</style\s*>|\z)`)
	rxA          = regexp.MustCompile(`(?is)<a\b[^>]*>`)
	rxFormOpen   = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	rxFormClose  = regexp.MustCompile(`(?i)</form`)
	rxFormField  = regexp.MustCompile(`(?is)<(?:input|select|textarea)\b[^>]*>`)
	rxHrefName   = "href"
	rxActionName = "action"
	rxMethodName = "method"
	rxNameAttr   = "name"

	attrRegexes = map[string]*regexp.Regexp{
		"href":   compileAttrRegex("href"),
		"action": compileAttrRegex("action"),
		"method": compileAttrRegex("method"),
		"name":   compileAttrRegex("name"),
	}
)

func compileAttrRegex(name string) *regexp.Regexp {
	// [^\w-] guards against matching data-href when looking for href.
	return regexp.MustCompile(`(?is)[^\w-]` + name + `\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
}

// attrValue extracts an attribute value from a single tag; quoted and
// unquoted forms supported. Returns "" when absent.
func attrValue(tag, name string) string {
	re := attrRegexes[name]
	m := re.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return ""
}

// sanitizeHTML removes comments and script/style bodies before extraction.
func sanitizeHTML(s string) string {
	s = rxComments.ReplaceAllString(s, " ")
	s = rxScript.ReplaceAllString(s, " ")
	s = rxStyle.ReplaceAllString(s, " ")
	return s
}
