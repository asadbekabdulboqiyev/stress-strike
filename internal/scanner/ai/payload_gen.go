package ai

// PayloadGenerator generates fuzzing payloads using a local LLM (Ollama).
// It communicates with http://localhost:11434/api/generate and sends a prompt
// asking the model to produce security-relevant HTTP fuzzing payloads.
//
// The design is "0 cost" — only the operator's CPU/GPU is used. No external
// API keys, no network access beyond localhost, no subscriptions.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OllamaConfig holds the connection details for the local Ollama instance.
type OllamaConfig struct {
	// BaseURL is the Ollama HTTP endpoint. Default: http://localhost:11434
	BaseURL string
	// Model is the LLM model name (e.g. "deepseek-coder:1.5b", "llama3").
	Model string
	// Timeout per request. Default: 30s
	Timeout time.Duration
	// Temperature controls randomness. 0.0 = deterministic, 1.0 = creative.
	Temperature float32
}

// DefaultOllamaConfig returns saner defaults for fuzzing use-cases.
func DefaultOllamaConfig() OllamaConfig {
	return OllamaConfig{
		BaseURL:     "http://localhost:11434",
		Model:       "deepseek-coder:1.5b",
		Timeout:     30 * time.Second,
		Temperature: 0.1,
	}
}

// PayloadInfo describes one generated payload.
type PayloadInfo struct {
	Label     string // e.g. "query-param", "header-injection"
	Raw       string // the raw string to send
	Mutation  string // human-readable category
	Intrusive bool   // whether this modifies state
	Reason    string // why the model chose this
}

// GeneratePayloads sends a prompt to the local Ollama instance and returns a
// list of security-relevant fuzzing payloads. The prompt asks the model to
// generate HTTP request mutations targeting common vulnerabilities (SQLi, XSS,
// path traversal, header injection, etc.).
//
// The caller must ensure Ollama is running and the model is pulled:
//
//	ollama pull deepseek-coder:1.5b
//
// This function is "0 cost" — it only uses the operator's local compute.
func GeneratePayloads(cfg OllamaConfig, prompt string) ([]PayloadInfo, error) {
	// Fill in only the fields the caller left empty. Replacing the whole config
	// here would silently discard a custom BaseURL or Temperature whenever the
	// caller omitted the model name.
	if cfg.Model == "" {
		cfg.Model = DefaultOllamaConfig().Model
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultOllamaConfig().BaseURL
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultOllamaConfig().Timeout
	}

	endpoint := cfg.BaseURL + "/api/generate"
	jsonPayload := map[string]any{
		"model":  cfg.Model,
		"prompt": prompt,
		"stream": false,
		"format": "json",
		"options": map[string]any{
			"temperature": cfg.Temperature,
		},
	}
	jsonBytes, err := json.Marshal(jsonPayload)
	if err != nil {
		return nil, fmt.Errorf("ai: marshal payload request: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, fmt.Errorf("ai: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("ai: request to ollama: %w", err)
	}
	defer resp.Body.Close()

	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ai: read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ai: ollama returned %d: %s", resp.StatusCode, string(resBody))
	}

	// Ollama returns: {"model": "...", "created_at": "...", "response": "...", "done": true, "context": [...]}
	var result struct {
		Response string `json:"response"`
		Done     bool   `json:"done"`
	}
	if err := json.Unmarshal(resBody, &result); err != nil {
		return nil, fmt.Errorf("ai: parse ollama response: %w", err)
	}

	if !result.Done {
		return nil, fmt.Errorf("ai: ollama request not done")
	}

	// The model returns plain text; we parse lines as "label|payload|reason"
	var payloads []PayloadInfo
	for _, line := range strings.Split(result.Response, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Expect format: Label | Payload | Reason | Intrusive
		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 2 {
			continue
		}
		p := PayloadInfo{
			Label:  strings.TrimSpace(parts[0]),
			Raw:    strings.TrimSpace(parts[1]),
			Reason: "",
		}
		if len(parts) >= 3 {
			p.Reason = strings.TrimSpace(parts[2])
		}
		if len(parts) >= 4 {
			p.Intrusive = strings.TrimSpace(parts[3]) == "1" || strings.ToLower(strings.TrimSpace(parts[3])) == "true"
		}
		payloads = append(payloads, p)
	}

	return payloads, nil
}

// --- Prompt templates ------------------------------------------------------

// FuzzingPrompt returns a system prompt that asks the LLM to act as a security
// fuzzing engineer. It generates HTTP payloads for common web vulnerabilities.
//
// The prompt is designed to produce output in the format:
//
//	Label | RawPayload | Reason | Intrusive(0|1)
//
// Examples of labels: query-param, header, body, path-param, traversal, sqli, xss, write
func FuzzingPrompt(targetDesc string) string {
	system := `You are an AI security fuzzing engineer. Your job is to generate HTTP fuzzing payloads
that a coverage-guided fuzzer can use to probe web applications for vulnerabilities.

TARGET DESCRIPTION: ` + targetDesc + `

Generate exactly 20 payloads. For each payload, output ONE line in this exact format:

Label | RawPayload | Reason | Intrusive(0|1)

Rules:
- Label must be one of: query-param, header, body, path-param, traversal, sqli, xss, write
- RawPayload should be a single HTTP parameter/value/piece that can be URL-encoded or body-injected
- Reason should be a brief note on what the payload targets (e.g. "SQL injection", "XSS", "path traversal")
- Intrusive is 1 if the payload modifies server state (PUT/DELETE/write methods), 0 otherwise
- Diversity: include various vulnerability types and injection locations
- NO markdown, NO explanations, ONLY the tab-separated format above

Example line:
query-param | q=<script>alert(1)</script> | XSS attempt | 0

Be creative but stay within responsible security testing bounds.`
	return system
}

// TargetDescription returns a human-readable description of the target for the LLM.
func TargetDescription(baseURL string, paths []string, intrusive bool) string {
	var b strings.Builder
	b.WriteString("Target: " + baseURL + "\n")
	b.WriteString("Endpoints: " + strings.Join(paths, ", ") + "\n")
	if intrusive {
		b.WriteString("Intrusive mode enabled: payloads may include state-changing mutations (PUT, DELETE, write methods).\n")
	} else {
		b.WriteString("Safe mode: only read-only probes (GET, query params, headers).\n")
	}
	b.WriteString("\nGenerate payloads that test: SQL injection, XSS, path traversal, header injection, command injection, and XXE.")
	return b.String()
}
