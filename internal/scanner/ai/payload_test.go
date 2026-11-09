package ai

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ollamaRequest mirrors the JSON body GeneratePayloads sends.
type ollamaRequest struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	Stream  bool           `json:"stream"`
	Format  string         `json:"format"`
	Options map[string]any `json:"options"`
}

// newOllamaServer starts a fake Ollama endpoint and returns it as a config.
func newOllamaServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, body ollamaRequest)) OllamaConfig {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/api/generate" {
			t.Errorf("path = %q, want /api/generate", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		var body ollamaRequest
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		handler(w, r, body)
	}))
	t.Cleanup(srv.Close)
	return OllamaConfig{BaseURL: srv.URL, Model: "test-model", Timeout: 5 * time.Second, Temperature: 0.3}
}

func TestGeneratePayloadsParsesModelOutput(t *testing.T) {
	cfg := newOllamaServer(t, func(w http.ResponseWriter, r *http.Request, body ollamaRequest) {
		if body.Model != "test-model" {
			t.Errorf("model = %q", body.Model)
		}
		if body.Prompt != "probe the login form" {
			t.Errorf("prompt = %q", body.Prompt)
		}
		if body.Stream {
			t.Error("stream should be false")
		}
		if body.Format != "json" {
			t.Errorf("format = %q, want json", body.Format)
		}
		if temp, ok := body.Options["temperature"].(float64); !ok || temp != 0.3 {
			t.Errorf("temperature = %v, want 0.3", body.Options["temperature"])
		}

		resp := map[string]any{
			"model": "test-model",
			"done":  true,
			"response": strings.Join([]string{
				"sqli | ' OR 1=1-- | SQL injection | 0",
				"xss | <script>alert(1)</script> | reflected XSS | true",
				"write | PUT /admin | state change | 1",
				"traversal | ../../etc/passwd | path traversal",
				"",
				"garbage line without delimiters",
				"header | X-Forwarded-For: 127.0.0.1 | spoofing | 0",
			}, "\n"),
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	payloads, err := GeneratePayloads(cfg, "probe the login form")
	if err != nil {
		t.Fatalf("GeneratePayloads: %v", err)
	}

	if len(payloads) != 5 {
		t.Fatalf("len = %d, want 5 (blank + malformed lines skipped): %+v", len(payloads), payloads)
	}

	first := payloads[0]
	if first.Label != "sqli" || first.Raw != "' OR 1=1--" || first.Reason != "SQL injection" || first.Intrusive {
		t.Errorf("payload[0] = %+v", first)
	}
	if !payloads[1].Intrusive {
		t.Errorf("payload[1] (true) should be intrusive: %+v", payloads[1])
	}
	if !payloads[2].Intrusive {
		t.Errorf("payload[2] (1) should be intrusive: %+v", payloads[2])
	}
	if payloads[3].Reason != "path traversal" || payloads[3].Intrusive {
		t.Errorf("payload[3] = %+v", payloads[3])
	}
	if payloads[4].Label != "header" || payloads[4].Raw != "X-Forwarded-For: 127.0.0.1" {
		t.Errorf("payload[4] = %+v", payloads[4])
	}
}

func TestGeneratePayloadsIntrusiveFalseVariants(t *testing.T) {
	cfg := newOllamaServer(t, func(w http.ResponseWriter, r *http.Request, body ollamaRequest) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"done": true,
			"response": strings.Join([]string{
				"a | one | r | 0",
				"b | two | r | false",
				"c | three | r | TRUE",
				"d | four | r | yes",
			}, "\n"),
		})
	})

	payloads, err := GeneratePayloads(cfg, "p")
	if err != nil {
		t.Fatalf("GeneratePayloads: %v", err)
	}
	want := []bool{false, false, true, false}
	if len(payloads) != len(want) {
		t.Fatalf("len = %d, want %d", len(payloads), len(want))
	}
	for i, w := range want {
		if payloads[i].Intrusive != w {
			t.Errorf("payload[%d].Intrusive = %v, want %v (%+v)", i, payloads[i].Intrusive, w, payloads[i])
		}
	}
}

func TestGeneratePayloadsEmptyResponseIsNotAnError(t *testing.T) {
	cfg := newOllamaServer(t, func(w http.ResponseWriter, r *http.Request, body ollamaRequest) {
		_ = json.NewEncoder(w).Encode(map[string]any{"done": true, "response": ""})
	})

	payloads, err := GeneratePayloads(cfg, "p")
	if err != nil {
		t.Fatalf("GeneratePayloads: %v", err)
	}
	if len(payloads) != 0 {
		t.Fatalf("len = %d, want 0", len(payloads))
	}
}

func TestGeneratePayloadsNotDone(t *testing.T) {
	cfg := newOllamaServer(t, func(w http.ResponseWriter, r *http.Request, body ollamaRequest) {
		_ = json.NewEncoder(w).Encode(map[string]any{"done": false, "response": "partial"})
	})

	if _, err := GeneratePayloads(cfg, "p"); err == nil || !strings.Contains(err.Error(), "not done") {
		t.Fatalf("error = %v, want not done", err)
	}
}

func TestGeneratePayloadsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`model "test-model" not found`))
	}))
	defer srv.Close()

	cfg := OllamaConfig{BaseURL: srv.URL, Model: "test-model", Timeout: 2 * time.Second}
	_, err := GeneratePayloads(cfg, "p")
	if err == nil || !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error = %v, want status and body", err)
	}
}

func TestGeneratePayloadsBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>not json</html>`))
	}))
	defer srv.Close()

	cfg := OllamaConfig{BaseURL: srv.URL, Model: "test-model", Timeout: 2 * time.Second}
	if _, err := GeneratePayloads(cfg, "p"); err == nil || !strings.Contains(err.Error(), "parse ollama response") {
		t.Fatalf("error = %v, want parse error", err)
	}
}

func TestGeneratePayloadsHonoursTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{"done": true, "response": "a | b"})
	}))
	defer srv.Close()

	cfg := OllamaConfig{BaseURL: srv.URL, Model: "test-model", Timeout: 30 * time.Millisecond}
	start := time.Now()
	_, err := GeneratePayloads(cfg, "p")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("call took %v, cfg.Timeout was not applied to the request", elapsed)
	}
}

func TestGeneratePayloadsConnectionRefused(t *testing.T) {
	cfg := OllamaConfig{BaseURL: "http://127.0.0.1:1", Model: "m", Timeout: time.Second}
	if _, err := GeneratePayloads(cfg, "p"); err == nil || !strings.Contains(err.Error(), "request to ollama") {
		t.Fatalf("error = %v, want request failure", err)
	}
}

func TestGeneratePayloadsInvalidBaseURL(t *testing.T) {
	cfg := OllamaConfig{BaseURL: "://bad", Model: "m", Timeout: time.Second}
	if _, err := GeneratePayloads(cfg, "p"); err == nil || !strings.Contains(err.Error(), "new request") {
		t.Fatalf("error = %v, want request construction error", err)
	}
}

func TestGeneratePayloadsFillsMissingFieldsOnly(t *testing.T) {
	cfg := newOllamaServer(t, func(w http.ResponseWriter, r *http.Request, body ollamaRequest) {
		// A custom BaseURL must survive even though Model was left empty.
		if body.Model != DefaultOllamaConfig().Model {
			t.Errorf("model = %q, want default", body.Model)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"done": true, "response": ""})
	})
	cfg.Model = ""
	cfg.Timeout = 0

	if _, err := GeneratePayloads(cfg, "p"); err != nil {
		t.Fatalf("GeneratePayloads: %v", err)
	}
}

func TestDefaultOllamaConfig(t *testing.T) {
	cfg := DefaultOllamaConfig()
	if cfg.BaseURL != "http://localhost:11434" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.Model == "" {
		t.Error("Model must have a default")
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", cfg.Timeout)
	}
	if cfg.Temperature <= 0 || cfg.Temperature > 1 {
		t.Errorf("Temperature = %v, want low-but-nonzero", cfg.Temperature)
	}
}

func TestFuzzingPrompt(t *testing.T) {
	p := FuzzingPrompt("https://example.test/login")
	for _, want := range []string{
		"TARGET DESCRIPTION: https://example.test/login",
		"Label | RawPayload | Reason | Intrusive(0|1)",
		"query-param, header, body, path-param, traversal, sqli, xss, write",
		"Generate exactly 20 payloads",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

func TestTargetDescription(t *testing.T) {
	intrusive := TargetDescription("https://t.test", []string{"/a", "/b"}, true)
	for _, want := range []string{"Target: https://t.test", "Endpoints: /a, /b", "Intrusive mode enabled", "PUT, DELETE"} {
		if !strings.Contains(intrusive, want) {
			t.Errorf("intrusive description missing %q:\n%s", want, intrusive)
		}
	}
	if strings.Contains(intrusive, "Safe mode") {
		t.Errorf("intrusive description must not claim safe mode:\n%s", intrusive)
	}

	safe := TargetDescription("https://t.test", nil, false)
	if !strings.Contains(safe, "Safe mode") {
		t.Errorf("safe description missing safe mode note:\n%s", safe)
	}
	if strings.Contains(safe, "Intrusive mode enabled") {
		t.Errorf("safe description must not claim intrusive mode:\n%s", safe)
	}
}
