package scanner

// crawler_test.go exercises the crawler against a small in-memory multi-page
// site: relative links, query-param URLs, POST/GET forms, an offsite target,
// a 404 page, binary content, and a root->alpha->root loop.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type crawlFixture struct {
	main      *httptest.Server
	offsite   *httptest.Server
	offHits   *atomic.Int64
	searchHit *atomic.Int64
}

func newCrawlFixture(t *testing.T) *crawlFixture {
	t.Helper()

	var offHits, searchHits atomic.Int64

	// "Offsite" is a second server so SameHostOnly can be observed exactly.
	offsite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="%s/">back home</a></body></html>`, r.Host) // link back, would loop if followed
	}))

	mux := http.NewServeMux()
	homeHTML := `<!doctype html><html><head><title>Home</title></head><body>
<a href="/alpha">Alpha</a>
<a href="/search?q=x&page=2">Search</a>
<a href="` + offsite.URL + `/off">Offsite</a>
<a href="mailto:x@y.z">Mail</a>
<a href="javascript:void(0)">JS</a>
<a href="/gone">Broken</a>
<a href="/asset.bin">Binary asset</a>
<form action="/login" method="post">
  <input name="username">
  <input type="password" name="password">
  <select name="role"><option value="a">a</option></select>
  <textarea name="notes"></textarea>
</form>
<!-- <a href="/commented-out">hidden in comment</a> -->
<script>var x = "<a href=\"/in-script\">nope</a>";</script>
</body></html>`
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, homeHTML)
	})
	mux.HandleFunc("/alpha", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>
<a href="/">Home</a>
<a href="/beta">Beta</a>
<form action="/contact" method="get">
  <input name="email">
  <textarea name="message"></textarea>
</form>
</body></html>`)
	})
	mux.HandleFunc("/beta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>
<a href="/">Home loop</a>
<a href="/search?q=zzz">Search variant</a>
</body></html>`)
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		searchHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>results</body></html>`)
	})
	mux.HandleFunc("/gone", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `<html><body><a href="/from-404">secret</a></body></html>`, http.StatusNotFound)
	})
	mux.HandleFunc("/asset.bin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		fmt.Fprint(w, `<html><body><a href="/hidden-in-binary">h</a></body></html>`) // must never be parsed
	})

	main := httptest.NewServer(mux)
	t.Cleanup(main.Close)
	t.Cleanup(offsite.Close)

	return &crawlFixture{main: main, offsite: offsite, offHits: &offHits, searchHit: &searchHits}
}

// findEndpoint locates the first endpoint matching url+kind ("" = any).
func findEndpoint(eps []Endpoint, rawURL, kind string) *Endpoint {
	for i := range eps {
		if eps[i].URL == rawURL && (kind == "" || eps[i].Kind == kind) {
			return &eps[i]
		}
	}
	return nil
}

func hasPrefixEndpoint(eps []Endpoint, prefix, kind string) bool {
	for _, ep := range eps {
		if strings.HasPrefix(ep.URL, prefix) && (kind == "" || ep.Kind == kind) {
			return true
		}
	}
	return false
}

func TestCrawlDiscoversOnSitePagesAndEndpoints(t *testing.T) {
	fx := newCrawlFixture(t)
	cr := NewCrawler(fx.main.URL, CrawlOptions{})
	res := cr.Crawl()

	if res == nil {
		t.Fatal("Crawl returned nil")
	}
	// Pages: /, /alpha, /beta, /search, /gone, /asset.bin (forms not crawled,
	// offsite/mailto/js/commented/binary-hidden targets excluded).
	wantPages := 6
	if res.Pages != wantPages {
		t.Errorf("Pages = %d, want %d (endpoints: %+v)", res.Pages, wantPages, endpointURLs(res.Endpoints))
	}

	if !hasPrefixEndpoint(res.Endpoints, fx.main.URL+"/alpha", "link") {
		t.Error("missing /alpha link endpoint")
	}

	// Query params extracted from discovered URLs.
	se := findEndpoint(res.Endpoints, fx.main.URL+"/search?q=x&page=2", "link")
	if se == nil {
		t.Fatalf("missing /search?q=x&page=2 endpoint; got %v", endpointURLs(res.Endpoints))
	}
	if len(se.Params) != 2 || se.Params[0] != "page" || se.Params[1] != "q" {
		t.Errorf("query params = %v, want [page q]", se.Params)
	}

	// Depth-2 pages reachable within default MaxDepth=3.
	if !hasPrefixEndpoint(res.Endpoints, fx.main.URL+"/beta", "link") {
		t.Error("missing /beta link endpoint")
	}

	// Never-discovered content.
	for _, bad := range []string{"/commented-out", "/in-script", "/hidden-in-binary", "/from-404"} {
		if hasPrefixEndpoint(res.Endpoints, fx.main.URL+bad, "") {
			t.Errorf("endpoint from hidden/binary/404 content leaked: %s", bad)
		}
	}

	// mailto/javascript skipped entirely.
	for _, ep := range res.Endpoints {
		if strings.HasPrefix(ep.URL, "mailto:") || strings.HasPrefix(ep.URL, "javascript:") {
			t.Errorf("non-http scheme recorded: %s", ep.URL)
		}
	}

	// /search fetched once despite two query variants on different pages.
	if n := fx.searchHit.Load(); n != 1 {
		t.Errorf("/search fetched %d times, want 1 (queue deduped by path)", n)
	}
}

func TestCrawlFormEndpointsCaptured(t *testing.T) {
	fx := newCrawlFixture(t)
	cr := NewCrawler(fx.main.URL, CrawlOptions{MaxDepth: 1})
	res := cr.Crawl()

	login := findEndpoint(res.Endpoints, fx.main.URL+"/login", "form")
	if login == nil {
		t.Fatalf("POST /login form endpoint missing; got %v", endpointURLs(res.Endpoints))
	}
	if login.Method != "POST" {
		t.Errorf("login method = %q, want POST", login.Method)
	}
	wantFields := map[string]bool{"username": true, "password": true, "role": true, "notes": true}
	if len(login.Params) != len(wantFields) {
		t.Errorf("login params = %v, want %v", login.Params, wantFields)
	}
	for _, p := range login.Params {
		if !wantFields[p] {
			t.Errorf("unexpected login field %q (all: %v)", p, login.Params)
		}
	}
	if login.FoundAt != fx.main.URL {
		t.Errorf("login FoundAt = %q, want %q", login.FoundAt, fx.main.URL)
	}

	contact := findEndpoint(res.Endpoints, fx.main.URL+"/contact", "form")
	if contact == nil {
		t.Fatal("GET /contact form endpoint missing")
	}
	if contact.Method != "GET" {
		t.Errorf("contact method = %q, want GET", contact.Method)
	}
	if len(contact.Params) != 2 || contact.Params[0] != "email" || contact.Params[1] != "message" {
		t.Errorf("contact params = %v, want [email message]", contact.Params)
	}
}

func TestCrawlSameHostOnly(t *testing.T) {
	fx := newCrawlFixture(t)

	t.Run("default skips offsite", func(t *testing.T) {
		cr := NewCrawler(fx.main.URL, CrawlOptions{})
		res := cr.Crawl()
		if n := fx.offHits.Load(); n != 0 {
			t.Errorf("offsite fetched %d times with SameHostOnly default, want 0", n)
		}
		for _, ep := range res.Endpoints {
			if strings.Contains(ep.URL, strings.TrimPrefix(fx.offsite.URL, "http://")) {
				t.Errorf("offsite endpoint recorded: %s", ep.URL)
			}
		}
	})

	t.Run("AllowOffsite follows", func(t *testing.T) {
		cr := NewCrawler(fx.main.URL, CrawlOptions{AllowOffsite: true, MaxDepth: 2})
		cr.Crawl()
		if n := fx.offHits.Load(); n < 1 {
			t.Error("offsite never fetched despite AllowOffsite=true")
		}
	})
}

func TestCrawlMaxPagesCap(t *testing.T) {
	fx := newCrawlFixture(t)
	cr := NewCrawler(fx.main.URL, CrawlOptions{MaxPages: 2})
	res := cr.Crawl()
	if res.Pages > 2 {
		t.Errorf("Pages = %d, want <= 2", res.Pages)
	}
	if res.Pages == 0 {
		t.Error("crawled nothing at all")
	}
}

func TestCrawlNoDuplicateEndpoints(t *testing.T) {
	fx := newCrawlFixture(t)
	cr := NewCrawler(fx.main.URL, CrawlOptions{})
	res := cr.Crawl()

	seen := map[string]int{}
	for _, ep := range res.Endpoints {
		k := endpointKey(ep.Method, ep.URL, ep.Params)
		seen[k]++
		if seen[k] > 1 {
			t.Errorf("duplicate endpoint key %q", k)
		}
	}
	if len(res.Endpoints) == 0 {
		t.Fatal("expected some endpoints")
	}
}

func TestCrawlDurationPositive(t *testing.T) {
	fx := newCrawlFixture(t)
	cr := NewCrawler(fx.main.URL, CrawlOptions{MaxPages: 1})
	res := cr.Crawl()
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", res.Duration)
	}
}

func TestCrawlDepthLimit(t *testing.T) {
	var chain *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="%s/l1">next</a></body></html>`, chain.URL)
	})
	for _, p := range []string{"/l1", "/l2"} {
		linkTo := map[string]string{"/l1": "/l2", "/l2": "/l3"}[p]
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body><a href="%s%s">next</a></body></html>`, chain.URL, linkTo)
		})
	}
	mux.HandleFunc("/l3", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>end of chain</body></html>`)
	})
	chain = httptest.NewServer(mux)
	defer chain.Close()

	tests := []struct {
		name     string
		maxDepth int
		want     int
	}{
		{"depth 1 fetches start + one hop", 1, 2},
		{"depth 2 fetches three hops", 2, 3},
		{"zero means default 3, covers whole chain", 0, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := NewCrawler(chain.URL, CrawlOptions{MaxDepth: tt.maxDepth})
			res := cr.Crawl()
			if res.Pages != tt.want {
				t.Errorf("MaxDepth=%d: Pages = %d, want %d", tt.maxDepth, res.Pages, tt.want)
			}
		})
	}
}

func TestCrawlMalformedHTMLNoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<<<>>> <a href=<broken <form <input name= <a href='unclosed </form>`)
	}))
	defer srv.Close()

	cr := NewCrawler(srv.URL, CrawlOptions{MaxPages: 5})
	res := cr.Crawl() // must not panic
	if res == nil {
		t.Fatal("nil result for malformed HTML")
	}
}

func TestCrawlClientInjection(t *testing.T) {
	fx := newCrawlFixture(t)
	cr := NewCrawler(fx.main.URL, CrawlOptions{MaxPages: 3})
	cr.Client = fx.main.Client() // injected client must be respected
	res := cr.Crawl()
	if res.Pages == 0 {
		t.Error("injected client produced no pages")
	}
}

// TestCrawlRedirectDoesNotLeaveHost verifies the crawler's redirect guard:
// a 302 pointing at a foreign host surfaces the redirect response and the
// foreign origin is never contacted.
func TestCrawlRedirectDoesNotLeaveHost(t *testing.T) {
	var crossHits int32
	cross := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&crossHits, 1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>evil</body></html>")
	}))
	defer cross.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cross.URL+"/steal", http.StatusFound)
	}))
	defer origin.Close()

	c := NewCrawler(origin.URL, CrawlOptions{MaxPages: 5})
	res := c.Crawl()

	if got := atomic.LoadInt32(&crossHits); got != 0 {
		t.Fatalf("foreign host was contacted %d time(s)", got)
	}
	if res.Pages != 1 {
		t.Fatalf("Pages = %d, want 1 (the surfaced redirect response)", res.Pages)
	}
}

// TestCrawlFollowsSameHostRedirect verifies redirects within the same host
// still work (the redirect guard must only cut cross-host hops).
func TestCrawlFollowsSameHostRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/home", http.StatusFound)
	})
	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/about">About</a></body></html>`)
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>about page</body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewCrawler(srv.URL, CrawlOptions{MaxPages: 10})
	res := c.Crawl()

	// "/" resolves through a same-host redirect to /home: the chain counts as
	// one fetched page whose HTML yields /about as the second page.
	if res.Pages != 2 {
		t.Fatalf("Pages = %d, want 2 (/, /about)", res.Pages)
	}
	foundAbout := false
	for _, ep := range res.Endpoints {
		if strings.HasSuffix(ep.URL, "/about") && ep.Method == "GET" {
			foundAbout = true
		}
	}
	if !foundAbout {
		t.Errorf("endpoint /about not discovered after same-host redirect: %v", endpointURLs(res.Endpoints))
	}
}

// endpointURLs is a compact debug helper for failure messages.
func endpointURLs(eps []Endpoint) []string {
	out := make([]string, 0, len(eps))
	for _, ep := range eps {
		out = append(out, ep.Method+" "+ep.URL+" "+strings.Join(ep.Params, "&"))
	}
	return out
}
