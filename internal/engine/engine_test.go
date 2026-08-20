package engine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"stress-strike/internal/config"
)

func TestRender(t *testing.T) {
	vars := map[string]string{"user": "user42", "token": "abc123"}
	got := render("POST {{user}}?t={{token}}", vars)
	want := "POST user42?t=abc123"
	if got != want {
		t.Errorf("render = %q, want %q", got, want)
	}
	got = render("{{unknown}}", vars)
	if got != "{{unknown}}" {
		t.Errorf("render unknown = %q, want kept as-is", got)
	}
}

func TestRenderBodyJSONEncoding(t *testing.T) {
	vars := map[string]string{"user": "u1", "note": `say "hi" \ ok`}
	got := renderBody(`{"username":"{{user}}","note":"{{note}}"}}`, vars)
	want := `{"username":"u1","note":"say \"hi\" \\ ok"}}`
	if got != want {
		t.Errorf("renderBody = %q, want %q", got, want)
	}
	got = renderBody(`{"qty":{{id}},"u":"{{user}}"}`, map[string]string{"id": "7", "user": "u2"})
	if got != `{"qty":7,"u":"u2"}` {
		t.Errorf("renderBody unquoted = %q", got)
	}
	got = renderBody(`plain {{user}}`, map[string]string{"user": "u3"})
	if got != "plain u3" {
		t.Errorf("renderBody plain = %q", got)
	}
}

func TestExtractValue(t *testing.T) {
	body := []byte(`{"data":{"token":"tok-1","nested":{"id":7}}}`)
	v, err := extractValue("json", "data.token", body, "")
	if err != nil || v != "tok-1" {
		t.Errorf("json extract = %q, %v", v, err)
	}
	v, err = extractValue("json", "data.nested.id", body, "")
	if err != nil || v != "7" {
		t.Errorf("json nested extract = %q, %v", v, err)
	}
	if _, err := extractValue("json", "data.missing", body, ""); err == nil {
		t.Errorf("expected error for missing json path")
	}

	v, err = extractValue("header", "X-Trace", nil, "trace-1")
	if err != nil || v != "trace-1" {
		t.Errorf("header extract = %q, %v", v, err)
	}
	if _, err := extractValue("header", "X-Trace", nil, ""); err == nil {
		t.Errorf("expected error for missing header")
	}

	v, err = extractValue("body", `id="([0-9]+)"`, []byte(`<div id="99"></div>`), "")
	if err != nil || v != "99" {
		t.Errorf("body regex extract = %q, %v", v, err)
	}
	if _, err := extractValue("body", `id="([0-9]+)"`, []byte("no match"), ""); err == nil {
		t.Errorf("expected error for unmatched body regex")
	}
}

func TestProfiles(t *testing.T) {
	steady, err := buildProfile(config.Profile{Type: config.ProfileSteady, Users: 100, Duration: 10})
	if err != nil {
		t.Fatal(err)
	}
	if steady.ConcurrencyAt(0) != 100 || steady.MaxConcurrency() != 100 {
		t.Errorf("steady profile mismatch: %d/%d", steady.ConcurrencyAt(0), steady.MaxConcurrency())
	}

	ramp, err := buildProfile(config.Profile{Type: config.ProfileLinearRamp, Users: 100, Duration: 10, RampUp: 10})
	if err != nil {
		t.Fatal(err)
	}
	if ramp.ConcurrencyAt(0) != 1 {
		t.Errorf("ramp at 0 = %d, want 1", ramp.ConcurrencyAt(0))
	}
	if got := ramp.ConcurrencyAt(5 * time.Second); got < 45 || got > 55 {
		t.Errorf("ramp at 5s = %d, want ~50", got)
	}
	if ramp.ConcurrencyAt(10*time.Second) != 100 {
		t.Errorf("ramp at 10s = %d, want 100", ramp.ConcurrencyAt(10*time.Second))
	}

	spike, err := buildProfile(config.Profile{Type: config.ProfileSpike, Users: 10, SpikeUsers: 5000, SpikeWarmup: 5, SpikeHold: 10, Duration: 30})
	if err != nil {
		t.Fatal(err)
	}
	if spike.ConcurrencyAt(4*time.Second) != 10 {
		t.Errorf("spike warmup concurrency = %d, want 10", spike.ConcurrencyAt(4*time.Second))
	}
	if spike.ConcurrencyAt(6*time.Second) != 5000 {
		t.Errorf("spike burst concurrency = %d, want 5000", spike.ConcurrencyAt(6*time.Second))
	}
	if spike.ConcurrencyAt(16*time.Second) != 10 {
		t.Errorf("spike after-hold concurrency = %d, want 10", spike.ConcurrencyAt(16*time.Second))
	}
	if spike.MaxConcurrency() != 5000 {
		t.Errorf("spike max = %d, want 5000", spike.MaxConcurrency())
	}
}

func TestProfilesSoakAndWave(t *testing.T) {
	soak, err := buildProfile(config.Profile{Type: config.ProfileSoak, Users: 100, Duration: 10})
	if err != nil {
		t.Fatal(err)
	}
	if soak.ConcurrencyAt(0) != 100 || soak.ConcurrencyAt(5*time.Second) != 100 || soak.MaxConcurrency() != 100 {
		t.Errorf("soak profile mismatch: got %d/%d/%d", soak.ConcurrencyAt(0), soak.ConcurrencyAt(5*time.Second), soak.MaxConcurrency())
	}
	if soak.Duration() != 10*time.Second {
		t.Errorf("soak duration = %s, want 10s", soak.Duration())
	}

	wave, err := buildProfile(config.Profile{Type: config.ProfileWave, Users: 100, Duration: 10, WavePeriod: 10})
	if err != nil {
		t.Fatal(err)
	}
	if wave.ConcurrencyAt(0) != 50 {
		t.Errorf("wave at 0 = %d, want 50", wave.ConcurrencyAt(0))
	}
	if got := wave.ConcurrencyAt(2500 * time.Millisecond); got < 98 || got > 101 {
		t.Errorf("wave at 2.5s (peak) = %d, want ~100", got)
	}
	if got := wave.ConcurrencyAt(7500 * time.Millisecond); got != 1 {
		t.Errorf("wave at 7.5s (trough) = %d, want 1", got)
	}
	if wave.MaxConcurrency() != 100 || wave.Duration() != 10*time.Second {
		t.Errorf("wave meta = %d/%s", wave.MaxConcurrency(), wave.Duration())
	}
}

func TestCheckAssertions(t *testing.T) {
	body := []byte(`{"data":{"token":"abc"},"ok":true}`)

	if err := checkAssertions([]config.Assertion{
		{Type: "status", Value: "200"},
		{Type: "json_path", Value: "data.token"},
		{Type: "regex", Value: `"ok":true`},
	}, 200, body); err != nil {
		t.Fatalf("all assertions should pass, got %v", err)
	}
	if err := checkAssertions([]config.Assertion{{Type: "status", Value: "2xx"}}, 201, body); err != nil {
		t.Fatalf("2xx should match 201: %v", err)
	}
	if err := checkAssertions([]config.Assertion{{Type: "status", Value: "5xx"}}, 503, body); err != nil {
		t.Fatalf("5xx should match 503: %v", err)
	}
	if err := checkAssertions([]config.Assertion{{Type: "status", Value: "200"}}, 500, body); err == nil {
		t.Error("expected failure for mismatched status")
	}
	if err := checkAssertions([]config.Assertion{{Type: "json_path", Value: "data.missing"}}, 200, body); err == nil {
		t.Error("expected failure for missing json path")
	}
	if err := checkAssertions([]config.Assertion{{Type: "regex", Value: "NOPE"}}, 200, body); err == nil {
		t.Error("expected failure for unmatched regex")
	}
	if err := checkAssertions([]config.Assertion{{Type: "status", Value: "abc"}}, 200, body); err == nil {
		t.Error("expected failure for invalid status assertion")
	}
	if err := checkAssertions([]config.Assertion{{Type: "nope", Value: "x"}}, 200, body); err == nil {
		t.Error("expected failure for unsupported assertion type")
	}
}

func TestWebSocketClient(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.TextMessage, []byte("echo:"+string(msg)))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	e := &Engine{}
	res, body := e.wsClient(context.Background(), wsURL, config.Step{Body: "hi"}, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("ws error: %v", res.errName)
	}
	if res.status != 101 {
		t.Errorf("ws status = %d, want 101", res.status)
	}
	if got := string(body); got != "echo:hi" {
		t.Errorf("ws body = %q, want %q", got, "echo:hi")
	}
}

func TestRawTCPClient(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("reply:" + string(buf[:n])))
	}()

	e := &Engine{}
	res, body := e.rawClient(context.Background(), "tcp", ln.Addr().String(), config.Step{Body: "ping"}, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("tcp error: %v", res.errName)
	}
	if res.status != 200 {
		t.Errorf("tcp status = %d, want 200", res.status)
	}
	if got := string(body); got != "reply:ping" {
		t.Errorf("tcp body = %q, want %q", got, "reply:ping")
	}
}

func TestRawUDPClient(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 256)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo([]byte("reply:"+string(buf[:n])), addr)
	}()

	e := &Engine{}
	res, body := e.rawClient(context.Background(), "udp", pc.LocalAddr().String(), config.Step{Body: "dgram"}, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("udp error: %v", res.errName)
	}
	if res.status != 200 {
		t.Errorf("udp status = %d, want 200", res.status)
	}
	if len(body) != 0 {
		t.Errorf("udp body = %q, want empty (fire-and-forget)", body)
	}
}
