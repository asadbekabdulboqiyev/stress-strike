package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// httpRequester adapts *http.Client to the Requester interface (Check always allows).
type httpRequester struct{ c *http.Client }

func (r *httpRequester) Check(ctx context.Context, method, rawURL string, intrusive bool) error {
	return nil
}
func (r *httpRequester) Do(req *http.Request) (*http.Response, error) { return r.c.Do(req) }

func startTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestDirBust(t *testing.T) {
	srv := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(200)
			w.Write([]byte(`<title>Admin Panel</title>`))
		case "/.env":
			w.WriteHeader(200)
			w.Write([]byte(`DB_PASSWORD=secret`))
		case "/robots.txt":
			w.WriteHeader(200)
			w.Write([]byte(`User-agent: *`))
		default:
			w.WriteHeader(404)
		}
	})

	ctx := context.Background()
	res := DirBust(ctx, srv.URL, []string{"/admin", "/.env", "/robots.txt", "/nonexistent"}, &httpRequester{c: srv.Client()})
	if res == nil {
		t.Fatal("DirBust returned nil")
	}
	if res.Target != srv.URL {
		t.Errorf("Target = %q, want %q", res.Target, srv.URL)
	}
	if res.Found != 3 {
		t.Errorf("Found = %d, want 3", res.Found)
	}
	if len(res.Entries) != 3 {
		t.Errorf("Entries = %d, want 3", len(res.Entries))
	}
	for _, e := range res.Entries {
		if e.StatusCode == 404 {
			t.Errorf("Entry %s should not be in results (404 filtered)", e.URL)
		}
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want positive", res.Duration)
	}
}

func TestDirBustDefaultPaths(t *testing.T) {
	srv := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<title>OK</title>`))
	})
	ctx := context.Background()
	res := DirBust(ctx, srv.URL, nil, &httpRequester{c: srv.Client()})
	if res == nil {
		t.Fatal("DirBust returned nil")
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want positive", res.Duration)
	}
}

func TestDirBustCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	srv := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	res := DirBust(ctx, srv.URL, []string{"/a", "/b"}, &httpRequester{c: srv.Client()})
	if res == nil {
		t.Fatal("DirBust returned nil")
	}
	if res.Found != 0 || len(res.Entries) != 0 {
		t.Errorf("cancelled: Found=%d Entries=%d, want 0/0", res.Found, len(res.Entries))
	}
}

func TestIoReadAllLimit(t *testing.T) {
	data := strings.Repeat("x", 1000)
	body, err := ioReadAllLimit(strings.NewReader(data), 500)
	if err != nil {
		t.Fatalf("ioReadAllLimit: %v", err)
	}
	if len(body) != 500 {
		t.Errorf("len(body) = %d, want 500", len(body))
	}
}

func TestExtractTitle(t *testing.T) {
	if got := extractTitle(`<html><title>Hello World</title></html>`); got != "Hello World" {
		t.Errorf("extractTitle = %q, want Hello World", got)
	}
	if got := extractTitle(`<html><body>no title</body></html>`); got != "" {
		t.Errorf("extractTitle = %q, want empty", got)
	}
	if got := extractTitle(`<title>Only start</html>`); got != "Only start</html>" {
		t.Errorf("extractTitle = %q, want Only start</html>", got)
	}
	if got := extractTitle(""); got != "" {
		t.Errorf("extractTitle(empty) = %q, want empty", got)
	}
}
