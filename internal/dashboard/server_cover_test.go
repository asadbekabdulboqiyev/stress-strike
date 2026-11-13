package dashboard

// server_cover_test.go — coverage for the HTTP shell in server.go: the ops
// endpoints (/healthz, /readyz, /metrics), the auth middleware wrapper, the
// panic recover, every route in serveApp, the WebSocket lifecycle, the
// broadcast dead-client sweep, ApplyAuth's RBAC flag parsing, attestation
// verification failures and the data-dir resolution.

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/demostore"
	"github.com/gorilla/websocket"
)

// --- ops endpoints ----------------------------------------------------------

func TestServeOpsDefaults(t *testing.T) {
	s := NewServer()

	tests := []struct {
		path     string
		wantCode int
		wantBody string
	}{
		{"/healthz", http.StatusOK, `{"status":"ok"}`},
		{"/readyz", http.StatusOK, `{"status":"ok"}`},
		{"/metrics", http.StatusNotFound, "404 page not found"},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != tc.wantCode {
			t.Errorf("%s = %d, want %d", tc.path, rec.Code, tc.wantCode)
		}
		if !strings.Contains(rec.Body.String(), tc.wantBody) {
			t.Errorf("%s body = %q, want one containing %q", tc.path, rec.Body.String(), tc.wantBody)
		}
		// Defense-in-depth headers ride on every response, ops included.
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s X-Frame-Options = %q", tc.path, got)
		}
	}
}

func TestServeOpsInjectedHandlers(t *testing.T) {
	s := NewServer()

	var hits []string
	handler := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits = append(hits, name)
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte(name))
		})
	}
	s.SetMetricsHandler(handler("metrics"))
	s.SetHealthHandlers(handler("live"), nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot || rec.Body.String() != "metrics" {
		t.Errorf("metrics = %d %q", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot || rec.Body.String() != "live" {
		t.Errorf("healthz = %d %q", rec.Code, rec.Body.String())
	}

	// No readiness handler was injected: the built-in default answers "ok".
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Errorf("readyz = %d %q", rec.Code, rec.Body.String())
	}

	if len(hits) != 2 {
		t.Errorf("handlers hit %v, want exactly metrics+live", hits)
	}
}

func TestServeHTTPOpsExemptFromAuth(t *testing.T) {
	s := NewServer()
	s.SetAuthMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	})

	// Orchestrator probes must never need credentials.
	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s behind auth = %d, want 200", path, rec.Code)
		}
	}

	// Everything else is gated.
	req := httptest.NewRequest(http.MethodGet, "/api/snapshot", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("app route behind auth = %d, want 401", rec.Code)
	}
}

func TestRecoverMiddlewareConvertsPanic(t *testing.T) {
	s := NewServer()

	prev := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prev)

	h := s.recoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	// Must not take the process down and must answer 500.
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal server error") {
		t.Errorf("body = %q", rec.Body.String())
	}

	// A handler that does not panic passes straight through.
	h = s.recoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("clean handler = %d, want 204", rec.Code)
	}
}

// --- serveApp routing -------------------------------------------------------

func TestServeAppScanRoutes(t *testing.T) {
	// Every scan route rejects GET with 405: the dispatcher reached the right
	// handler, and no probe was attempted.
	paths := []string{
		"/api/subdomain/scan",
		"/api/portscan",
		"/api/dirbust",
		"/api/sslscan",
		"/api/jwt/scan",
		"/api/graphql/scan",
		"/api/websocket/scan",
	}
	for _, path := range paths {
		s := NewServer()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", path, rec.Code)
		}
	}

	// The offensive-scan routes are dispatched too: a POST with a body the
	// decoder rejects proves the request reached the handler.
	for _, path := range []string{"/api/pentest/scan", "/api/crawl/scan", "/api/fuzz/scan"} {
		s := NewServer()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d, want 400", path, rec.Code)
		}
	}
}

func TestServeAppStaticAssets(t *testing.T) {
	s := NewServer()

	tests := []struct {
		path        string
		contentType string
		wantCode    int
	}{
		{"/style.css", "text/css; charset=utf-8", http.StatusOK},
		{"/app.js", "application/javascript; charset=utf-8", http.StatusOK},
		{"/", "text/html; charset=utf-8", http.StatusOK},
		{"/index.html", "text/html; charset=utf-8", http.StatusOK},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != tc.wantCode {
			t.Errorf("%s = %d, want %d", tc.path, rec.Code, tc.wantCode)
		}
		if got := rec.Header().Get("Content-Type"); got != tc.contentType {
			t.Errorf("%s Content-Type = %q, want %q", tc.path, got, tc.contentType)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s served an empty body", tc.path)
		}
	}

	for _, path := range []string{"/some/deep/route", "/.git/config", "/.env", "/debug/pprof", "/actuator", "/certificate"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, rec.Code)
		}
	}

	// TRACE must not be allowed on the dashboard UI/asset surface.
	for _, path := range []string{"/", "/style.css", "/app.js"} {
		req := httptest.NewRequest(http.MethodTrace, path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("TRACE %s = %d, want 405", path, rec.Code)
		}
	}
}

// --- WebSocket --------------------------------------------------------------

func dialDashboardWS(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	return conn
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestHandleWebSocketLifecycle(t *testing.T) {
	s := NewServer()
	s.SetRunState(&RunState{Status: "running"})

	var mu sync.Mutex
	var commands []string
	s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		mu.Lock()
		defer mu.Unlock()
		commands = append(commands, cmd)
	})

	srv := httptest.NewServer(s)
	defer srv.Close()

	conn := dialDashboardWS(t, srv)
	defer conn.Close()

	// The first frame is the state the UI paints from.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read init frame: %v", err)
	}
	var init struct {
		Type  string         `json:"type"`
		State map[string]any `json:"state"`
	}
	if err := json.Unmarshal(raw, &init); err != nil {
		t.Fatalf("decode init frame: %v\n%s", err, raw)
	}
	if init.Type != "init" {
		t.Errorf("first frame type = %q, want init", init.Type)
	}
	if init.State["status"] != "running" {
		t.Errorf("init state = %+v, want the live run state", init.State)
	}

	// Commands from the browser reach the handler verbatim.
	if err := conn.WriteJSON(map[string]any{
		"type": "start",
		"args": map[string]any{"target": "https://example.test"},
	}); err != nil {
		t.Fatalf("write command: %v", err)
	}
	waitFor(t, "the start command to be dispatched", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(commands) == 1
	})

	// A malformed frame is skipped, not fatal: the next good command still
	// arrives, which proves the read loop continued.
	if err := conn.WriteMessage(websocket.TextMessage, []byte("{")); err != nil {
		t.Fatalf("write malformed frame: %v", err)
	}
	if err := conn.WriteJSON(map[string]any{"type": "stop"}); err != nil {
		t.Fatalf("write second command: %v", err)
	}
	waitFor(t, "the stop command to be dispatched", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(commands) == 2
	})

	mu.Lock()
	got := append([]string(nil), commands...)
	mu.Unlock()
	if got[0] != "start" || got[1] != "stop" {
		t.Errorf("commands = %v, want [start stop]", got)
	}

	// The peer is registered while the socket is open.
	s.mu.RLock()
	open := len(s.clients)
	s.mu.RUnlock()
	if open != 1 {
		t.Errorf("clients = %d, want 1", open)
	}

	// Closing the client must drain the registry.
	conn.Close()
	waitFor(t, "the client to be removed", func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return len(s.clients) == 0
	})
}

func TestHandleWebSocketConnectionCap(t *testing.T) {
	s := NewServer()
	for i := 0; i < maxWSConnections; i++ {
		s.wsSem <- struct{}{}
	}
	defer func() {
		for i := 0; i < maxWSConnections; i++ {
			<-s.wsSem
		}
	}()

	rec := httptest.NewRecorder()
	s.handleWebSocket(rec, httptest.NewRequest(http.MethodGet, "/ws", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("full cap = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "too many websocket connections") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestHandleWebSocketRejectsPlainHTTP(t *testing.T) {
	s := NewServer()
	rec := httptest.NewRecorder()
	// A plain GET without the Upgrade handshake headers: the upgrader refuses
	// and the handler returns without touching the client registry.
	s.handleWebSocket(rec, httptest.NewRequest(http.MethodGet, "/ws", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("plain GET /ws = %d, want 400", rec.Code)
	}
	s.mu.RLock()
	n := len(s.clients)
	s.mu.RUnlock()
	select {
	case s.wsSem <- struct{}{}:
		<-s.wsSem
	default:
		t.Error("upgrade failure leaked a websocket slot")
	}
	if n != 0 {
		t.Errorf("registry after a failed upgrade: %d client(s)", n)
	}
}

func TestBroadcastDropsDeadClients(t *testing.T) {
	s := NewServer()

	// A peer that completes the WebSocket handshake and then hangs up. The
	// resulting client conn never enters a read loop here, so writing to it
	// fails deterministically instead of racing the handler's cleanup.
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Abortive close: the kernel sends RST instead of FIN, so the client
		// side fails its next write immediately (no half-close grace).
		if tcp, ok := c.UnderlyingConn().(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = c.Close()
	}))
	defer peer.Close()

	dead, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(peer.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	defer dead.Close()
	// Drain the close so the socket is provably unusable.
	_ = dead.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := dead.ReadMessage(); err == nil {
		t.Fatal("peer did not close the connection")
	}

	s.mu.Lock()
	s.clients[dead] = true
	s.mu.Unlock()

	s.UpdateSnapshot(&LiveSnapshot{StatusCodes: map[int]uint64{}})
	s.mu.RLock()
	n := len(s.clients)
	s.mu.RUnlock()
	if n != 0 {
		t.Errorf("snapshot broadcast left %d dead client(s) registered", n)
	}

	// Same sweep for the run-state broadcaster.
	s.mu.Lock()
	s.clients[dead] = true
	s.mu.Unlock()
	s.SetRunState(&RunState{Status: "idle"})
	s.mu.RLock()
	n = len(s.clients)
	s.mu.RUnlock()
	if n != 0 {
		t.Errorf("run-state broadcast left %d dead client(s) registered", n)
	}
}

// --- auth wiring ------------------------------------------------------------

func TestApplyAuthNoCredentials(t *testing.T) {
	s := NewServer()
	if a := s.ApplyAuth(AuthOptions{}); a != nil {
		a.Close()
		t.Fatal("ApplyAuth installed auth without any credential")
	}
	if s.authMiddleware != nil {
		t.Error("auth middleware installed with no credentials")
	}
}

func TestApplyAuthParsesRBACRoles(t *testing.T) {
	s := NewServer()
	a := s.ApplyAuth(AuthOptions{
		Tokens:      []string{"secret-token"},
		RBACEnabled: true,
		// One well-formed entry, one malformed one that must be skipped, and
		// one with padded roles that must be trimmed.
		RBACRole: []string{"alice:admin, viewer", "broken", ":solo"},
	})
	if a == nil {
		t.Fatal("ApplyAuth returned nil with a token enrolled")
	}
	defer a.Close()

	if s.authMiddleware == nil {
		t.Fatal("middleware was not installed")
	}

	// No credentials on the request: refused.
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/snapshot", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous = %d, want 401", rec.Code)
	}

	// Valid bearer token: allowed through to the snapshot handler.
	req := httptest.NewRequest(http.MethodGet, "/api/snapshot", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	var snap LiveSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
}

func TestGetAttestationInfoRoundTrip(t *testing.T) {
	s := NewServer()
	if got := s.GetAttestationInfo(); got.Exists {
		t.Fatalf("fresh server reports an attestation: %+v", got)
	}

	want := AttestationInfo{Exists: true, RunID: "run-9", BundlePath: "/tmp/b.json", PubKeyHex: "aa"}
	s.SetAttestationInfo(want)
	if got := s.GetAttestationInfo(); got != want {
		t.Errorf("GetAttestationInfo = %+v, want %+v", got, want)
	}
}

// --- attestation verification ----------------------------------------------

func writeDashboardBundle(t *testing.T) (string, string) {
	t.Helper()
	coord := mustKeyDashboard(t)
	w := mustKeyDashboard(t)
	run := attest.Run{
		Target:     "https://example.test/api",
		Profile:    "constant-rps",
		DurationNS: 5_000_000_000,
		PlannedRPS: attest.Decimal("100.000"),
	}
	specs := []workerSpecDashboard{
		{id: "w1", kp: w, recs: synthRecordsDashboard("w1", 1_000_000_000, 3, 1_000_000, 1_000_000, 10_000)},
	}
	b, samples := produceBundleDashboard(t, coord, run, specs, true)

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := attest.SaveBundle(b, bundlePath); err != nil {
		t.Fatalf("SaveBundle: %v", err)
	}
	samplesPath := filepath.Join(dir, "samples.jsonl")
	f, err := os.Create(samplesPath)
	if err != nil {
		t.Fatalf("create samples: %v", err)
	}
	for _, recs := range samples {
		if err := attest.WriteSamples(f, recs); err != nil {
			t.Fatalf("WriteSamples: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close samples: %v", err)
	}
	return bundlePath, samplesPath
}

func TestVerifyAttestationLoadFailures(t *testing.T) {
	t.Run("missing bundle", func(t *testing.T) {
		out := verifyAttestation(filepath.Join(t.TempDir(), "nope.json"), "")
		if out["valid"] != false {
			t.Errorf("valid = %v, want false", out["valid"])
		}
		reason, _ := out["reason"].(string)
		if !strings.Contains(reason, "load bundle failed") {
			t.Errorf("reason = %q", reason)
		}
		if out["bundlePath"] == "" {
			t.Error("response does not name the bundle it failed to load")
		}
	})

	t.Run("missing samples", func(t *testing.T) {
		bundlePath, _ := writeDashboardBundle(t)
		badSamples := filepath.Join(t.TempDir(), "missing.jsonl")
		out := verifyAttestation(bundlePath, badSamples)
		if out["valid"] != false {
			t.Errorf("valid = %v, want false", out["valid"])
		}
		reason, _ := out["reason"].(string)
		if !strings.Contains(reason, "load samples failed") {
			t.Errorf("reason = %q", reason)
		}
		if out["samplesPath"] != badSamples {
			t.Errorf("samplesPath = %v, want %q", out["samplesPath"], badSamples)
		}
	})

	t.Run("valid bundle and samples", func(t *testing.T) {
		bundlePath, samplesPath := writeDashboardBundle(t)
		out := verifyAttestation(bundlePath, samplesPath)
		if out["valid"] != true {
			t.Fatalf("valid = %v, reason = %v", out["valid"], out["reason"])
		}
		stats, ok := out["samplesStats"].(map[string]interface{})
		if !ok {
			t.Fatalf("samplesStats missing: %+v", out)
		}
		if lines, _ := stats["lines"].(int); lines == 0 {
			t.Errorf("samplesStats.lines = %v", stats["lines"])
		}
	})
}

func TestVerifyAttestationTamperedBundle(t *testing.T) {
	t.Run("run metadata", func(t *testing.T) {
		bundlePath, samplesPath := writeDashboardBundle(t)

		raw, err := os.ReadFile(bundlePath)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		// Flip the attacker-visible run target: the signature no longer
		// covers it.
		run, ok := doc["run"].(map[string]any)
		if !ok {
			t.Fatalf("bundle has no run object: %s", raw)
		}
		run["target"] = "https://evil.example/exfil"
		tampered, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bundlePath, tampered, 0o600); err != nil {
			t.Fatal(err)
		}

		out := verifyAttestation(bundlePath, samplesPath)
		if out["valid"] != false {
			t.Fatalf("tampered bundle verified as valid: %+v", out)
		}
		if reason, _ := out["reason"].(string); reason == "" {
			t.Fatal("invalid verdict carries no reason")
		}
	})

	t.Run("worker claim", func(t *testing.T) {
		bundlePath, samplesPath := writeDashboardBundle(t)

		raw, err := os.ReadFile(bundlePath)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		workers, ok := doc["workers"].([]any)
		if !ok || len(workers) == 0 {
			t.Fatalf("bundle has no workers: %s", raw)
		}
		w, ok := workers[0].(map[string]any)
		if !ok {
			t.Fatalf("worker is not an object: %v", workers[0])
		}
		agg, ok := w["aggregate"].(map[string]any)
		if !ok {
			t.Fatalf("worker has no aggregate: %v", w)
		}
		// Inflate the worker's own claim; the commit no longer matches.
		count, _ := agg["count"].(float64)
		agg["count"] = count + 1
		tampered, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bundlePath, tampered, 0o600); err != nil {
			t.Fatal(err)
		}

		out := verifyAttestation(bundlePath, samplesPath)
		if out["valid"] != false {
			t.Fatalf("worker tamper verified as valid: %+v", out)
		}
		reason, _ := out["reason"].(string)
		if reason == "" || reason == "verification failed" {
			t.Errorf("reason = %q, want a specific explanation", reason)
		}
	})
}

// --- demo store control plane ----------------------------------------------

func TestDemoStoreStartAlreadyRunning(t *testing.T) {
	// A live listener at the store's URL makes Start report "already running"
	// and spawn nothing.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	s := NewServer()
	s.store = demostore.New(demostore.Options{URL: upstream.URL})

	req := httptest.NewRequest(http.MethodPost, "/api/demo-store/start", nil)
	rec := httptest.NewRecorder()
	s.handleDemoStoreStart(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["ok"] != true || out["already_running"] != true {
		t.Errorf("body = %+v, want ok+already_running", out)
	}
	if out["protection"] != true {
		t.Errorf("protection = %v, want true", out["protection"])
	}
	if out["url"] != upstream.URL {
		t.Errorf("url = %v, want %q", out["url"], upstream.URL)
	}
}

// freeLocalPort returns a loopback port that nothing is listening on right
// now. It is only a hint: the point is that the test does not depend on the
// machine's default demo-store address.
func freeLocalPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return strconv.Itoa(port)
}

func TestDemoStoreStartFailureIsReported(t *testing.T) {
	// No checkout above the temp dir and no PATH entry: the store cannot be
	// located, so the endpoint reports the failure instead of spawning.
	t.Chdir(t.TempDir())
	t.Setenv("PATH", "")

	s := NewServer()
	// Point the supervisor at a port nothing listens on. The default address
	// belongs to the machine, not to the test: when a demo store happens to
	// run there, the endpoint answers "already running" with 200 and the
	// locate failure this test is about is never reached.
	s.store = demostore.New(demostore.Options{URL: "http://127.0.0.1:" + freeLocalPort(t)})
	req := httptest.NewRequest(http.MethodPost, "/api/demo-store/start", nil)
	rec := httptest.NewRecorder()
	s.handleDemoStoreStart(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("start without a store = %d, want 500\nbody: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["ok"] != false {
		t.Errorf("ok = %v, want false", out["ok"])
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "demo store not found") {
		t.Errorf("error = %q, want the locate failure", out["error"])
	}
}

// --- data directory ---------------------------------------------------------

func TestGetDashboardDataDirCreatesTree(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	dir, err := getDashboardDataDir()
	if err != nil {
		t.Fatalf("getDashboardDataDir: %v", err)
	}
	if !strings.HasSuffix(dir, filepath.Join("Sift", "dashboard")) {
		t.Errorf("dir = %q, want it to end with Sift/dashboard", dir)
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		t.Fatalf("dir was not created: %v", err)
	}
}

func TestGetDashboardDataDirMkdirFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", home)

	// Block the platform's own config directory instead of hardcoding the
	// macOS one: os.UserConfigDir resolves HOME on macOS, XDG_CONFIG_HOME on
	// Linux and AppData on Windows, so only a derived path is portable.
	cfg, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("os.UserConfigDir: %v", err)
	}
	// A regular file where the parent directory must be: MkdirAll fails.
	blocker := filepath.Join(cfg, "Sift")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		if mkErr := os.MkdirAll(filepath.Dir(blocker), 0o750); mkErr != nil {
			t.Fatal(mkErr)
		}
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if dir, err := getDashboardDataDir(); err == nil {
		t.Fatalf("getDashboardDataDir succeeded with a file blocking the path: %q", dir)
	}
}

func TestGetDashboardDataDirNoHome(t *testing.T) {
	// Every platform gets its own "nowhere to look" env so the fallback chain
	// fails on all three: os.UserConfigDir reads XDG_CONFIG_HOME (Linux) and
	// AppData (Windows); os.UserHomeDir reads HOME (Unix) and USERPROFILE.
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")
	if dir, err := getDashboardDataDir(); err == nil {
		t.Fatalf("getDashboardDataDir without a home = %q, want an error", dir)
	}
}
