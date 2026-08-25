package anomaly

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// --- Types ------------------------------------------------------------------

type AnomalyResult struct {
	Timestamp   time.Time    `json:"timestamp"`
	Patterns    []Pattern    `json:"patterns"`
	Anomalies   []Anomaly    `json:"anomalies"`
	RootCauses  []RootCause  `json:"root_causes"`
	Predictions []Prediction `json:"predictions"`
	Score       float64      `json:"score"` // 0-100, higher = more anomalies
	Summary     string       `json:"summary"`
}

type Pattern struct {
	Type        string   `json:"type"`       // gc_pause, thread_exhaustion, network_saturation, disk_io, connection_pool, error_burst
	Confidence  float64  `json:"confidence"` // 0-1
	Description string   `json:"description"`
	Evidence    []string `json:"evidence"`
}

type Anomaly struct {
	Type      string    `json:"type"` // spike, drop, drift, burst, plateau
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Baseline  float64   `json:"baseline"`
	Deviation float64   `json:"deviation"`
	Severity  string    `json:"severity"` // critical, high, medium, low
	Timestamp time.Time `json:"timestamp"`
}

type RootCause struct {
	Pattern     string  `json:"pattern"`
	Probability float64 `json:"probability"`
	Explanation string  `json:"explanation"`
	Fix         string  `json:"fix"`
}

type Prediction struct {
	Metric     string    `json:"metric"`
	At         time.Time `json:"at"`
	Predicted  float64   `json:"predicted"`
	Confidence float64   `json:"confidence"`
	Action     string    `json:"action"`
}

// MetricData represents time-series metric data
type MetricData struct {
	Timestamps []time.Time
	Values     []float64
	Name       string
}

// --- Statistical Anomaly Detection ------------------------------------------

// DetectAnomalies finds anomalies in metric data using statistical methods
func DetectAnomalies(data *MetricData) []Anomaly {
	if len(data.Values) < 10 {
		return nil
	}

	anomalies := make([]Anomaly, 0)

	// Calculate statistics
	mean := calcMean(data.Values)
	stddev := calcStdDev(data.Values, mean)
	q1, q3 := calcQuartiles(data.Values)
	iqr := q3 - q1
	median := calcMedian(data.Values)

	// Z-score based detection
	for i, v := range data.Values {
		if stddev > 0 {
			zscore := math.Abs((v - mean) / stddev)
			if zscore > 3.0 {
				severity := "low"
				if zscore > 5.0 {
					severity = "high"
				} else if zscore > 4.0 {
					severity = "medium"
				}
				anomalies = append(anomalies, Anomaly{
					Type:      "spike",
					Metric:    data.Name,
					Value:     v,
					Baseline:  mean,
					Deviation: zscore,
					Severity:  severity,
					Timestamp: data.Timestamps[i],
				})
			}
		}
	}

	// IQR based detection
	for i, v := range data.Values {
		if v < q1-1.5*iqr || v > q3+1.5*iqr {
			anomalies = append(anomalies, Anomaly{
				Type:      "outlier",
				Metric:    data.Name,
				Value:     v,
				Baseline:  median,
				Deviation: math.Abs(v-median) / iqr,
				Severity:  "medium",
				Timestamp: data.Timestamps[i],
			})
		}
	}

	// Moving average drift detection
	windowSize := min(10, len(data.Values)/5)
	if windowSize >= 5 {
		for i := windowSize; i < len(data.Values); i++ {
			window := data.Values[i-windowSize : i]
			recent := data.Values[i]
			windowMean := calcMean(window)

			if windowMean > 0 && math.Abs(recent-windowMean)/windowMean > 0.5 {
				anomalies = append(anomalies, Anomaly{
					Type:      "drift",
					Metric:    data.Name,
					Value:     recent,
					Baseline:  windowMean,
					Deviation: math.Abs(recent-windowMean) / windowMean,
					Severity:  "medium",
					Timestamp: data.Timestamps[i],
				})
			}
		}
	}

	// Error burst detection (consecutive high values)
	consecutiveThreshold := 5
	consecutive := 0
	for i, v := range data.Values {
		if v > mean+2*stddev {
			consecutive++
			if consecutive >= consecutiveThreshold {
				anomalies = append(anomalies, Anomaly{
					Type:      "burst",
					Metric:    data.Name,
					Value:     v,
					Baseline:  mean,
					Deviation: float64(consecutive),
					Severity:  "high",
					Timestamp: data.Timestamps[i],
				})
				consecutive = 0
			}
		} else {
			consecutive = 0
		}
	}

	return anomalies
}

// --- Pattern Classification -------------------------------------------------

// ClassifyPatterns identifies performance patterns from metrics
func ClassifyPatterns(metrics map[string]*MetricData) []Pattern {
	patterns := make([]Pattern, 0)

	// GC Pause Detection
	if latency, ok := metrics["latency"]; ok {
		if gcPattern := detectGCPauses(latency); gcPattern != nil {
			patterns = append(patterns, *gcPattern)
		}
	}

	// Thread Pool Exhaustion
	if concurrency, ok := metrics["active_users"]; ok {
		if latency, ok := metrics["latency"]; ok {
			if tpPattern := detectThreadExhaustion(concurrency, latency); tpPattern != nil {
				patterns = append(patterns, *tpPattern)
			}
		}
	}

	// Network Saturation
	if rps, ok := metrics["rps"]; ok {
		if latency, ok := metrics["latency"]; ok {
			if netPattern := detectNetworkSaturation(rps, latency); netPattern != nil {
				patterns = append(patterns, *netPattern)
			}
		}
	}

	// Connection Pool Exhaustion
	if errors, ok := metrics["errors"]; ok {
		if connPattern := detectConnectionPoolExhaustion(errors); connPattern != nil {
			patterns = append(patterns, *connPattern)
		}
	}

	// Error Burst
	if errors, ok := metrics["errors"]; ok {
		if burstPattern := detectErrorBurst(errors); burstPattern != nil {
			patterns = append(patterns, *burstPattern)
		}
	}

	return patterns
}

func detectGCPauses(latency *MetricData) *Pattern {
	if len(latency.Values) < 20 {
		return nil
	}

	// Look for periodic spikes (GC pauses are usually periodic)
	sorted := make([]float64, len(latency.Values))
	copy(sorted, latency.Values)
	sort.Float64s(sorted)
	p99 := sorted[int(float64(len(sorted))*0.99)]
	mean := calcMean(latency.Values)

	// Count spikes above 3x mean
	spikeCount := 0
	for _, v := range latency.Values {
		if v > mean*3 {
			spikeCount++
		}
	}

	spikeRatio := float64(spikeCount) / float64(len(latency.Values))

	if spikeRatio > 0.02 && p99 > mean*5 {
		return &Pattern{
			Type:        "gc_pause",
			Confidence:  math.Min(0.9, spikeRatio*10),
			Description: fmt.Sprintf("Periodic latency spikes detected (p99=%.1fms, %.1fx above mean). Likely GC pauses.", p99, p99/mean),
			Evidence: []string{
				fmt.Sprintf("P99 latency: %.1fms (%.1fx above mean)", p99, p99/mean),
				fmt.Sprintf("Spike count: %d (%.1f%% of requests)", spikeCount, spikeRatio*100),
				"Periodic pattern consistent with stop-the-world GC",
			},
		}
	}
	return nil
}

func detectThreadExhaustion(concurrency, latency *MetricData) *Pattern {
	if len(concurrency.Values) < 10 || len(latency.Values) < 10 {
		return nil
	}

	// If latency increases linearly with concurrency, thread pool is exhausted
	n := min(len(concurrency.Values), len(latency.Values))
	corr := calcCorrelation(concurrency.Values[:n], latency.Values[:n])

	if corr > 0.7 {
		return &Pattern{
			Type:        "thread_exhaustion",
			Confidence:  math.Min(0.95, corr),
			Description: fmt.Sprintf("Latency strongly correlates with concurrency (r=%.2f). Thread pool exhaustion likely.", corr),
			Evidence: []string{
				fmt.Sprintf("Correlation: %.2f", corr),
				"Latency increases as concurrent users increase",
				fmt.Sprintf("Max concurrency: %.0f", calcMax(concurrency.Values)),
				"Increase thread pool size or implement connection pooling",
			},
		}
	}
	return nil
}

func detectNetworkSaturation(rps, latency *MetricData) *Pattern {
	if len(rps.Values) < 10 || len(latency.Values) < 10 {
		return nil
	}

	// If RPS plateaus while latency keeps increasing
	n := min(len(rps.Values), len(latency.Values))
	rpsSlope := calcSlope(rps.Values[max(0, n-20):n])
	latSlope := calcSlope(latency.Values[max(0, n-20):n])

	if rpsSlope < 0.01 && latSlope > 0.1 {
		return &Pattern{
			Type:        "network_saturation",
			Confidence:  0.75,
			Description: "RPS plateau with increasing latency suggests network buffer saturation.",
			Evidence: []string{
				fmt.Sprintf("RPS slope: %.4f (plateau)", rpsSlope),
				fmt.Sprintf("Latency slope: %.4f (increasing)", latSlope),
				"Network bandwidth or buffer limit reached",
			},
		}
	}
	return nil
}

func detectConnectionPoolExhaustion(errors *MetricData) *Pattern {
	if len(errors.Values) < 10 {
		return nil
	}

	// Look for sudden error increase (connection pool exhaustion)
	n := len(errors.Values)
	firstHalf := errors.Values[:n/2]
	secondHalf := errors.Values[n/2:]

	avg1 := calcMean(firstHalf)
	avg2 := calcMean(secondHalf)

	if avg1 > 0 && avg2/avg1 > 3 {
		return &Pattern{
			Type:        "connection_pool_exhaustion",
			Confidence:  math.Min(0.85, avg2/(avg1*3)),
			Description: fmt.Sprintf("Error rate jumped %.1fx in second half. Connection pool exhaustion likely.", avg2/avg1),
			Evidence: []string{
				fmt.Sprintf("First half avg errors: %.1f", avg1),
				fmt.Sprintf("Second half avg errors: %.1f", avg2),
				fmt.Sprintf("Increase: %.1fx", avg2/avg1),
				"Increase connection pool size or add connection recycling",
			},
		}
	}
	return nil
}

func detectErrorBurst(errors *MetricData) *Pattern {
	if len(errors.Values) < 5 {
		return nil
	}

	// Find consecutive error bursts
	maxBurst := 0
	currentBurst := 0
	threshold := calcMean(errors.Values) + calcStdDev(errors.Values, calcMean(errors.Values))

	for _, v := range errors.Values {
		if v > threshold {
			currentBurst++
			if currentBurst > maxBurst {
				maxBurst = currentBurst
			}
		} else {
			currentBurst = 0
		}
	}

	if maxBurst >= 3 {
		return &Pattern{
			Type:        "error_burst",
			Confidence:  math.Min(0.9, float64(maxBurst)/10),
			Description: fmt.Sprintf("Error burst detected: %d consecutive high-error data points.", maxBurst),
			Evidence: []string{
				fmt.Sprintf("Max burst length: %d", maxBurst),
				fmt.Sprintf("Threshold: %.1f errors", threshold),
				"Consecutive errors indicate cascading failure",
			},
		}
	}
	return nil
}

// --- Root Cause Analysis ----------------------------------------------------

func AnalyzeRootCauses(patterns []Pattern, anomalies []Anomaly) []RootCause {
	causes := make([]RootCause, 0)

	for _, p := range patterns {
		switch p.Type {
		case "gc_pause":
			causes = append(causes, RootCause{
				Pattern:     "gc_pause",
				Probability: p.Confidence,
				Explanation: "Go/Java runtime garbage collection is causing stop-the-world pauses. This happens when heap memory fills up.",
				Fix:         "Tune GC settings (GOGC for Go, -XX:MaxGCPauseMillis for Java), reduce allocations, use object pooling",
			})
		case "thread_exhaustion":
			causes = append(causes, RootCause{
				Pattern:     "thread_exhaustion",
				Probability: p.Confidence,
				Explanation: "Thread/goroutine pool is saturated. New requests wait in queue, causing latency increase.",
				Fix:         "Increase worker pool size, use async I/O, implement backpressure",
			})
		case "network_saturation":
			causes = append(causes, RootCause{
				Pattern:     "network_saturation",
				Probability: p.Confidence,
				Explanation: "Network buffer or bandwidth limit reached. Packets are queued/dropped.",
				Fix:         "Increase TCP buffer sizes, use HTTP/2 multiplexing, add connection pooling",
			})
		case "connection_pool_exhaustion":
			causes = append(causes, RootCause{
				Pattern:     "connection_pool_exhaustion",
				Probability: p.Confidence,
				Explanation: "Database/service connection pool exhausted. Requests block waiting for available connections.",
				Fix:         "Increase pool size, add connection recycling, implement circuit breakers",
			})
		case "error_burst":
			causes = append(causes, RootCause{
				Pattern:     "error_burst",
				Probability: p.Confidence,
				Explanation: "Cascading failure detected. One component failure triggers others.",
				Fix:         "Add retry with backoff, implement circuit breakers, add bulkheads",
			})
		}
	}

	return causes
}

// --- AI Integration ---------------------------------------------------------

type AIClient struct {
	Provider string // "gemini", "ollama", "openai"
	APIKey   string
	Model    string
	BaseURL  string
}

func NewAIClient() *AIClient {
	client := &AIClient{
		Provider: "ollama",
		Model:    "llama3.2",
		BaseURL:  "http://localhost:11434",
	}

	// Auto-detect from environment
	if key := os.Getenv("GEMINI_API_KEY"); key != "" {
		client.Provider = "gemini"
		client.APIKey = key
		client.Model = "gemini-2.0-flash"
		client.BaseURL = "https://generativelanguage.googleapis.com/v1beta"
	} else if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		client.Provider = "openai"
		client.APIKey = key
		client.Model = "gpt-4o-mini"
		client.BaseURL = "https://api.openai.com/v1"
	}

	return client
}

// AnalyzeWithAI sends metrics to AI for deep analysis
func (c *AIClient) AnalyzeWithAI(metrics map[string]*MetricData, patterns []Pattern, anomalies []Anomaly) (*AnomalyResult, error) {
	// Build prompt
	prompt := c.buildPrompt(metrics, patterns, anomalies)

	// Call AI
	response, err := c.callAI(prompt)
	if err != nil {
		return nil, fmt.Errorf("AI analysis failed: %w", err)
	}

	// Parse response
	result := c.parseResponse(response, patterns, anomalies)
	return result, nil
}

func (c *AIClient) buildPrompt(metrics map[string]*MetricData, patterns []Pattern, anomalies []Anomaly) string {
	var b strings.Builder

	b.WriteString("You are a performance engineering expert. Analyze the following load test metrics and identify anomalies, root causes, and predictions.\n\n")

	b.WriteString("## Metrics Summary\n")
	for name, data := range metrics {
		if len(data.Values) > 0 {
			mean := calcMean(data.Values)
			stddev := calcStdDev(data.Values, mean)
			sorted := make([]float64, len(data.Values))
			copy(sorted, data.Values)
			sort.Float64s(sorted)
			p50 := sorted[int(float64(len(sorted))*0.5)]
			p95 := sorted[int(float64(len(sorted))*0.95)]
			p99 := sorted[int(float64(len(sorted))*0.99)]
			b.WriteString(fmt.Sprintf("- %s: mean=%.1f stddev=%.1f p50=%.1f p95=%.1f p99=%.1f min=%.1f max=%.1f\n",
				name, mean, stddev, p50, p95, p99, sorted[0], sorted[len(sorted)-1]))
		}
	}

	b.WriteString("\n## Detected Patterns\n")
	for _, p := range patterns {
		b.WriteString(fmt.Sprintf("- [%s] (confidence: %.0f%%) %s\n", p.Type, p.Confidence*100, p.Description))
	}

	b.WriteString("\n## Detected Anomalies\n")
	for _, a := range anomalies[:min(10, len(anomalies))] {
		b.WriteString(fmt.Sprintf("- [%s] %s: value=%.1f baseline=%.1f deviation=%.1f (%s)\n",
			a.Severity, a.Type, a.Value, a.Baseline, a.Deviation, a.Timestamp.Format("15:04:05")))
	}

	b.WriteString("\n## Please provide:\n")
	b.WriteString("1. Root cause analysis (probability for each)\n")
	b.WriteString("2. Specific recommendations to fix each issue\n")
	b.WriteString("3. Predictions for what will happen if load increases 2x\n")
	b.WriteString("4. Priority action items\n")
	b.WriteString("\nRespond in JSON format with fields: root_causes[], recommendations[], predictions[], priority_actions[]\n")

	return b.String()
}

func (c *AIClient) callAI(prompt string) (string, error) {
	switch c.Provider {
	case "gemini":
		return c.callGemini(prompt)
	case "ollama":
		return c.callOllama(prompt)
	case "openai":
		return c.callOpenAI(prompt)
	default:
		return "", fmt.Errorf("unsupported AI provider: %s", c.Provider)
	}
}

func (c *AIClient) callGemini(prompt string) (string, error) {
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", c.BaseURL, c.Model, c.APIKey)

	body := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
	}

	jsonBody, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return string(data), nil
	}

	// Extract text from Gemini response
	if candidates, ok := result["candidates"].([]interface{}); ok && len(candidates) > 0 {
		if candidate, ok := candidates[0].(map[string]interface{}); ok {
			if content, ok := candidate["content"].(map[string]interface{}); ok {
				if parts, ok := content["parts"].([]interface{}); ok && len(parts) > 0 {
					if part, ok := parts[0].(map[string]interface{}); ok {
						if text, ok := part["text"].(string); ok {
							return text, nil
						}
					}
				}
			}
		}
	}

	return "", fmt.Errorf("unexpected Gemini response format")
}

func (c *AIClient) callOllama(prompt string) (string, error) {
	url := c.BaseURL + "/api/generate"

	body := map[string]interface{}{
		"model":  c.Model,
		"prompt": prompt,
		"stream": false,
	}

	jsonBody, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return string(data), nil
	}

	if response, ok := result["response"].(string); ok {
		return response, nil
	}

	return "", fmt.Errorf("unexpected Ollama response format")
}

func (c *AIClient) callOpenAI(prompt string) (string, error) {
	url := c.BaseURL + "/chat/completions"

	body := map[string]interface{}{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	jsonBody, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return string(data), nil
	}

	if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if msg, ok := choice["message"].(map[string]interface{}); ok {
				if content, ok := msg["content"].(string); ok {
					return content, nil
				}
			}
		}
	}

	return "", fmt.Errorf("unexpected OpenAI response format")
}

func (c *AIClient) parseResponse(response string, patterns []Pattern, anomalies []Anomaly) *AnomalyResult {
	result := &AnomalyResult{
		Timestamp: time.Now(),
		Patterns:  patterns,
		Anomalies: anomalies,
		Score:     calcAnomalyScore(anomalies),
	}

	// Try to parse JSON response
	var aiResult map[string]interface{}
	if err := json.Unmarshal([]byte(response), &aiResult); err == nil {
		if rcs, ok := aiResult["root_causes"].([]interface{}); ok {
			for _, rc := range rcs {
				if rcMap, ok := rc.(map[string]interface{}); ok {
					cause := RootCause{
						Pattern:     getString(rcMap, "pattern", "unknown"),
						Probability: getFloat(rcMap, "probability", 0.5),
						Explanation: getString(rcMap, "explanation", ""),
						Fix:         getString(rcMap, "fix", ""),
					}
					result.RootCauses = append(result.RootCauses, cause)
				}
			}
		}
		if preds, ok := aiResult["predictions"].([]interface{}); ok {
			for _, p := range preds {
				if pMap, ok := p.(map[string]interface{}); ok {
					pred := Prediction{
						Metric:     getString(pMap, "metric", "unknown"),
						Predicted:  getFloat(pMap, "predicted", 0),
						Confidence: getFloat(pMap, "confidence", 0.5),
						Action:     getString(pMap, "action", ""),
					}
					result.Predictions = append(result.Predictions, pred)
				}
			}
		}
	}

	// If no root causes from AI, use statistical analysis
	if len(result.RootCauses) == 0 {
		result.RootCauses = AnalyzeRootCauses(patterns, anomalies)
	}

	// Generate summary
	result.Summary = c.generateSummary(result)

	return result
}

func (c *AIClient) generateSummary(result *AnomalyResult) string {
	var b strings.Builder

	if result.Score > 70 {
		b.WriteString("CRITICAL: Multiple severe anomalies detected. Immediate action required.\n")
	} else if result.Score > 40 {
		b.WriteString("WARNING: Performance anomalies detected. Review recommended.\n")
	} else if result.Score > 20 {
		b.WriteString("INFO: Minor anomalies detected. Monitor closely.\n")
	} else {
		b.WriteString("HEALTHY: No significant anomalies detected.\n")
	}

	if len(result.RootCauses) > 0 {
		b.WriteString("\nTop root causes:\n")
		for i, rc := range result.RootCauses {
			if i >= 3 {
				break
			}
			b.WriteString(fmt.Sprintf("  %d. %s (%.0f%% probability)\n", i+1, rc.Pattern, rc.Probability*100))
		}
	}

	return b.String()
}

func calcAnomalyScore(anomalies []Anomaly) float64 {
	score := 0.0
	for _, a := range anomalies {
		switch a.Severity {
		case "critical":
			score += 25
		case "high":
			score += 15
		case "medium":
			score += 8
		case "low":
			score += 3
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

// --- Statistical Helpers ----------------------------------------------------

func calcMean(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}

func calcStdDev(data []float64, mean float64) float64 {
	if len(data) < 2 {
		return 0
	}
	sum := 0.0
	for _, v := range data {
		sum += (v - mean) * (v - mean)
	}
	return math.Sqrt(sum / float64(len(data)-1))
}

func calcMedian(data []float64) float64 {
	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)
	if len(sorted)%2 == 0 {
		return (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	}
	return sorted[len(sorted)/2]
}

func calcQuartiles(data []float64) (float64, float64) {
	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)
	q1 := sorted[int(float64(len(sorted))*0.25)]
	q3 := sorted[int(float64(len(sorted))*0.75)]
	return q1, q3
}

func calcCorrelation(x, y []float64) float64 {
	n := min(len(x), len(y))
	if n < 3 {
		return 0
	}
	meanX := calcMean(x[:n])
	meanY := calcMean(y[:n])

	var sumXY, sumX2, sumY2 float64
	for i := 0; i < n; i++ {
		dx := x[i] - meanX
		dy := y[i] - meanY
		sumXY += dx * dy
		sumX2 += dx * dx
		sumY2 += dy * dy
	}

	if sumX2 == 0 || sumY2 == 0 {
		return 0
	}
	return sumXY / math.Sqrt(sumX2*sumY2)
}

func calcSlope(data []float64) float64 {
	n := len(data)
	if n < 2 {
		return 0
	}
	var sumXY, sumX, sumY, sumX2 float64
	for i, v := range data {
		sumXY += float64(i) * v
		sumX += float64(i)
		sumY += v
		sumX2 += float64(i) * float64(i)
	}
	denom := float64(n)*sumX2 - sumX*sumX
	if denom == 0 {
		return 0
	}
	return (float64(n)*sumXY - sumX*sumY) / denom
}

func calcMax(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	max := data[0]
	for _, v := range data {
		if v > max {
			max = v
		}
	}
	return max
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func getString(m map[string]interface{}, key, def string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func getFloat(m map[string]interface{}, key string, def float64) float64 {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return def
}
