package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"stress-strike/internal/anomaly"
)

func main() {
	inputJSON := flag.String("input", "", "Load test report JSON to analyze")
	provider := flag.String("provider", "", "AI provider (gemini, ollama, openai) — auto-detect from env")
	model := flag.String("model", "", "AI model name (default: auto)")
	outputJSON := flag.String("output-json", "", "Export results to JSON file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
╔═══════════════════════════════════════════════════════════════╗
║  stress-strike ai — AI Anomaly Detector                      ║
║                                                               ║
║  • Latency pattern classification (GC, thread pool, network)  ║
║  • Statistical anomaly detection (Z-score, IQR, drift)       ║
║  • Root cause analysis with AI (Gemini/Ollama/OpenAI)        ║
║  • Predictive scaling recommendations                        ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
  stress-strike-ai -input report.json [flags]

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  # Analyze a load test report
  stress-strike-ai -input report.json

  # Analyze with Gemini AI
  GEMINI_API_KEY=xxx stress-strike-ai -input report.json

  # Analyze with local Ollama
  stress-strike-ai -input report.json -provider ollama -model llama3.2

  # Export AI analysis
  stress-strike-ai -input report.json -output-json analysis.json
`)
	}
	flag.Parse()

	if *inputJSON == "" {
		fmt.Fprintln(os.Stderr, "Error: -input flag is required")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  stress-strike ai — AI Anomaly Detector                     ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")

	// Load metrics from JSON
	fmt.Printf("  Loading: %s\n", *inputJSON)
	metrics, err := loadMetrics(*inputJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error loading metrics: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  Loaded %d metrics\n", len(metrics))
	for name, data := range metrics {
		fmt.Printf("    - %s: %d data points\n", name, len(data.Values))
	}
	fmt.Println()

	// Statistical detection
	fmt.Println("  [1/3] Statistical anomaly detection...")
	anomalies := make([]anomaly.Anomaly, 0)
	for name, data := range metrics {
		data.Name = name
		a := anomaly.DetectAnomalies(data)
		anomalies = append(anomalies, a...)
	}
	fmt.Printf("    Found %d anomalies\n", len(anomalies))

	// Pattern classification
	fmt.Println("  [2/3] Pattern classification...")
	patterns := anomaly.ClassifyPatterns(metrics)
	fmt.Printf("    Found %d patterns\n", len(patterns))

	for _, p := range patterns {
		fmt.Printf("    - [%s] (confidence: %.0f%%) %s\n", p.Type, p.Confidence*100, p.Description)
	}
	fmt.Println()

	// AI Analysis
	fmt.Println("  [3/3] AI analysis...")
	aiClient := anomaly.NewAIClient()
	if *provider != "" {
		aiClient.Provider = *provider
	}
	if *model != "" {
		aiClient.Model = *model
	}

	fmt.Printf("    Provider: %s | Model: %s\n", aiClient.Provider, aiClient.Model)

	result, err := aiClient.AnalyzeWithAI(metrics, patterns, anomalies)
	if err != nil {
		fmt.Printf("    AI analysis error: %v\n", err)
		fmt.Println("    Falling back to statistical analysis...")
		result = &anomaly.AnomalyResult{
			Timestamp:  time.Now(),
			Patterns:   patterns,
			Anomalies:  anomalies,
			RootCauses: anomaly.AnalyzeRootCauses(patterns, anomalies),
			Score:      calcScore(anomalies),
		}
		result.Summary = generateFallbackSummary(result)
	}

	// Print results
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  ANALYSIS RESULTS")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println(result.Summary)

	if len(anomalies) > 0 {
		fmt.Println("  Anomalies:")
		for _, a := range anomalies {
			severityIcon := map[string]string{
				"critical": "[!]",
				"high":     "[*]",
				"medium":   "[-]",
				"low":      "[.]",
			}
			fmt.Printf("    %s [%s] %s: %.1f (baseline: %.1f, deviation: %.1f)\n",
				severityIcon[a.Severity], a.Severity, a.Type, a.Value, a.Baseline, a.Deviation)
		}
		fmt.Println()
	}

	if len(result.RootCauses) > 0 {
		fmt.Println("  Root Causes:")
		for i, rc := range result.RootCauses {
			fmt.Printf("    %d. %s (%.0f%% probability)\n", i+1, rc.Pattern, rc.Probability*100)
			fmt.Printf("       %s\n", rc.Explanation)
			fmt.Printf("       Fix: %s\n", rc.Fix)
		}
		fmt.Println()
	}

	if len(result.Predictions) > 0 {
		fmt.Println("  Predictions:")
		for _, p := range result.Predictions {
			fmt.Printf("    - %s: predicted %.1f (%.0f%% confidence)\n", p.Metric, p.Predicted, p.Confidence*100)
			fmt.Printf("      Action: %s\n", p.Action)
		}
		fmt.Println()
	}

	fmt.Printf("  Anomaly Score: %.0f/100\n", result.Score)
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// Export
	if *outputJSON != "" {
		f, err := os.Create(*outputJSON)
		if err != nil {
			fmt.Printf("  Error creating file: %v\n", err)
		} else {
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			enc.Encode(result)
			fmt.Printf("\n  JSON report: %s\n", *outputJSON)
		}
	}
}

func loadMetrics(path string) (map[string]*anomaly.MetricData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Try to parse as stress-strike report format
	var report struct {
		Latency struct {
			Average float64 `json:"average"`
			P50     float64 `json:"p50"`
			P95     float64 `json:"p95"`
			P99     float64 `json:"p99"`
			Max     float64 `json:"max"`
		} `json:"latency"`
		Requests struct {
			Total  int     `json:"total"`
			Errors int     `json:"errors"`
			RPS    float64 `json:"rps"`
		} `json:"requests"`
		Timeline []struct {
			Timestamp string  `json:"timestamp"`
			RPS       float64 `json:"rps"`
			Latency   float64 `json:"latency"`
			Errors    int     `json:"errors"`
			Users     int     `json:"users"`
		} `json:"timeline"`
	}

	if err := json.NewDecoder(f).Decode(&report); err != nil {
		return nil, err
	}

	metrics := make(map[string]*anomaly.MetricData)

	// If timeline data exists, use it
	if len(report.Timeline) > 0 {
		latencyData := &anomaly.MetricData{Name: "latency"}
		rpsData := &anomaly.MetricData{Name: "rps"}
		errorData := &anomaly.MetricData{Name: "errors"}
		userData := &anomaly.MetricData{Name: "active_users"}

		for _, t := range report.Timeline {
			ts, _ := time.Parse(time.RFC3339, t.Timestamp)
			if ts.IsZero() {
				ts = time.Now()
			}
			latencyData.Timestamps = append(latencyData.Timestamps, ts)
			latencyData.Values = append(latencyData.Values, t.Latency)
			rpsData.Values = append(rpsData.Values, t.RPS)
			errorData.Values = append(errorData.Values, float64(t.Errors))
			userData.Values = append(userData.Values, float64(t.Users))
		}

		metrics["latency"] = latencyData
		metrics["rps"] = rpsData
		metrics["errors"] = errorData
		metrics["active_users"] = userData
	} else {
		// Generate synthetic data from summary stats
		latencyData := &anomaly.MetricData{
			Name:       "latency",
			Timestamps: make([]time.Time, 30),
			Values:     make([]float64, 30),
		}
		for i := 0; i < 30; i++ {
			latencyData.Timestamps[i] = time.Now().Add(-time.Duration(30-i) * time.Second)
			latencyData.Values[i] = report.Latency.Average + (float64(i%5)-2)*report.Latency.Average*0.1
		}
		metrics["latency"] = latencyData
	}

	return metrics, nil
}

func calcScore(anomalies []anomaly.Anomaly) float64 {
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

func generateFallbackSummary(result *anomaly.AnomalyResult) string {
	summary := ""
	if result.Score > 70 {
		summary = "CRITICAL: Multiple severe anomalies detected. Immediate action required.\n"
	} else if result.Score > 40 {
		summary = "WARNING: Performance anomalies detected. Review recommended.\n"
	} else if result.Score > 20 {
		summary = "INFO: Minor anomalies detected. Monitor closely.\n"
	} else {
		summary = "HEALTHY: No significant anomalies detected.\n"
	}
	return summary
}
