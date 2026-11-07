package dashboard

// sslscan_graphql_test.go — handler coverage for /api/sslscan and
// /api/graphql/scan: method/origin guards, request validation, the single-scan
// semaphore, the authorization gate and both scan outcomes (success and
// refusal) against loopback servers.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postTo(t *testing.T, h http.HandlerFunc, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestHandleSSLScanGuards(t *testing.T) {
	s := owaspTestServer(t)

	rec := httptest.NewRecorder()
	s.handleSSLScan(rec, httptest.NewRequest(http.MethodGet, "/api/sslscan", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", rec.Code)
	}

	rec = postTo(t, s.handleSSLScan, "/api/sslscan", `{"target":"https://127.0.0.1:1"}`, map[string]string{"Origin": "http://evil.example"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin status = %d, want 403", rec.Code)
	}
}

func TestHandleSSLScanRejectsBadRequests(t *testing.T) {
	s := owaspTestServer(t)

	rec := postTo(t, s.handleSSLScan, "/api/sslscan", `{"target":`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}

	rec = postTo(t, s.handleSSLScan, "/api/sslscan", `{"target":"not a url"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid target status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}

	rec = postTo(t, s.handleSSLScan, "/api/sslscan", `{"unknown":1}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

func TestHandleSSLScanBusy(t *testing.T) {
	s := owaspTestServer(t)
	s.owaspSem <- struct{}{}
	defer func() { <-s.owaspSem }()

	rec := postTo(t, s.handleSSLScan, "/api/sslscan", `{"target":"https://127.0.0.1:1"}`, nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("busy status = %d, want 409 (%s)", rec.Code, rec.Body.String())
	}
}

func TestHandleSSLScanTLSHost(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()

	s := owaspTestServer(t)
	rec := postTo(t, s.handleSSLScan, "/api/sslscan", `{"target":"`+target.URL+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var out SSLScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if !out.OK || out.Target == "" {
		t.Errorf("result = %+v, want ok with a target", out)
	}
	// ScanSSL captures the negotiated parameters without verifying trust, so a
	// completed handshake must surface a cipher and a TLS version.
	if out.Cipher == "" || out.Version == "" {
		t.Errorf("result = %+v, want cipher and version from a completed handshake", out)
	}
	if len(out.SANs) == 0 {
		t.Errorf("result = %+v, want the certificate SANs", out)
	}
}

func TestHandleSSLScanPlainHTTPSchemeDefaultsTo443(t *testing.T) {
	// An http:// target with no explicit port is scanned on :80; nothing is
	// listening, so the scan reports an unreachable host instead of failing the
	// request.
	s := owaspTestServer(t)
	rec := postTo(t, s.handleSSLScan, "/api/sslscan", `{"target":"http://127.0.0.1"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var out SSLScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Valid {
		t.Error("Valid = true for a closed port, want false")
	}
}

func TestHandleGraphQLScanGuards(t *testing.T) {
	s := owaspTestServer(t)

	rec := httptest.NewRecorder()
	s.handleGraphQLScan(rec, httptest.NewRequest(http.MethodGet, "/api/graphql/scan", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", rec.Code)
	}

	rec = postTo(t, s.handleGraphQLScan, "/api/graphql/scan", `{"endpoint":"http://127.0.0.1:1/graphql"}`,
		map[string]string{"Origin": "http://evil.example"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin status = %d, want 403", rec.Code)
	}
}

func TestHandleGraphQLScanRejectsBadRequests(t *testing.T) {
	s := owaspTestServer(t)

	rec := postTo(t, s.handleGraphQLScan, "/api/graphql/scan", `{"endpoint":`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON status = %d, want 400", rec.Code)
	}
	rec = postTo(t, s.handleGraphQLScan, "/api/graphql/scan", `{"endpoint":"::::"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid endpoint status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

func TestHandleGraphQLScanBusy(t *testing.T) {
	s := owaspTestServer(t)
	s.owaspSem <- struct{}{}
	defer func() { <-s.owaspSem }()

	rec := postTo(t, s.handleGraphQLScan, "/api/graphql/scan", `{"endpoint":"http://127.0.0.1:1/graphql"}`, nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("busy status = %d, want 409 (%s)", rec.Code, rec.Body.String())
	}
}

func TestHandleGraphQLScanIntrospectionEnabled(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User","kind":"OBJECT","fields":[]}]}}}`))
	}))
	defer target.Close()

	s := owaspTestServer(t)
	rec := postTo(t, s.handleGraphQLScan, "/api/graphql/scan", `{"endpoint":"`+target.URL+`/graphql"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var out GraphQLScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if !out.OK || !out.Reachable {
		t.Errorf("result = %+v, want ok and reachable", out)
	}
	if !out.Introspection {
		t.Error("Introspection = false, want true for a schema response")
	}
	if out.Schema != "Query" {
		t.Errorf("Schema = %q, want Query", out.Schema)
	}
	if len(out.Types) == 0 {
		t.Error("Types empty, want the advertised type list")
	}
}

func TestHandleGraphQLScanNonJSON(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not graphql</html>"))
	}))
	defer target.Close()

	s := owaspTestServer(t)
	rec := postTo(t, s.handleGraphQLScan, "/api/graphql/scan", `{"endpoint":"`+target.URL+`/graphql"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var out GraphQLScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Reachable {
		t.Error("Reachable = false for a responding server, want true")
	}
	if len(out.Issues) == 0 {
		t.Error("Issues empty for a non-JSON reply, want a hint")
	}
}
