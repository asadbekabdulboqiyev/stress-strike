package replay

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ReplayWorker replays a single captured packet stream at configured rate
type ReplayWorker struct {
	id        int
	config    *ReplayConfig
	capture   *Capture
	packets   []*Packet
	stopCh    chan struct{}
	mu        sync.Mutex
	latencies []time.Duration
	errors    []error
	conn      http.Client
}

// NewReplayWorker creates a new replay worker
func NewReplayWorker(id int, config *ReplayConfig, capture *Capture, packets []*Packet) *ReplayWorker {
	// Build a TLS config that always enforces a safe minimum TLS version.
	tlsCfg := TLSConfigFromKeys(config.TLSKeys, config.SkipTLSVerify)
	if len(config.TLSKeys) == 0 {
		tlsCfg.MinVersion = tls.VersionTLS12
	}

	transport := &http.Transport{
		TLSClientConfig:    tlsCfg,
		MaxIdleConns:       config.MaxConcurrency,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: false,
	}

	return &ReplayWorker{
		id:        id,
		config:    config,
		capture:   capture,
		packets:   packets,
		stopCh:    make(chan struct{}),
		latencies: make([]time.Duration, 0, len(packets)),
		conn:      http.Client{Transport: transport, Timeout: 30 * time.Second},
	}
}

// Run replays all packets at the configured rate multiplier
func (rw *ReplayWorker) Run() error {
	total := len(rw.packets)
	if total == 0 {
		return nil
	}

	// Calculate delay between requests based on rate multiplier
	// rate=1.0 means real-time, rate=10.0 means 10x faster
	if rw.config.RateMultiplier <= 0 {
		rw.config.RateMultiplier = 1.0
	}
	delay := time.Duration(float64(time.Second) / rw.config.RateMultiplier)

	rateTicker := time.NewTicker(delay)
	defer rateTicker.Stop()

	for i := 0; i < total; i++ {
		select {
		case <-rw.stopCh:
			return fmt.Errorf("worker %d stopped", rw.id)
		case <-rateTicker.C:
			pkt := rw.packets[i]

			start := time.Now()
			err := rw.replayPacket(pkt)
			latency := time.Since(start)

			rw.mu.Lock()
			rw.latencies = append(rw.latencies, latency)
			if err != nil {
				rw.errors = append(rw.errors, err)
			}
			rw.mu.Unlock()
		}
	}
	return nil
}

// Stop signals the worker to stop
func (rw *ReplayWorker) Stop() {
	close(rw.stopCh)
}

// replayPacket replays a single HTTP request
func (rw *ReplayWorker) replayPacket(pkt *Packet) error {
	if pkt.Method == "" || pkt.URL == "" {
		return nil // skip non-HTTP packets
	}

	// Apply base URL override if configured
	reqURL := pkt.URL
	if rw.config.BaseURL != "" {
		u, err := url.Parse(pkt.URL)
		if err != nil {
			return fmt.Errorf("parse URL: %w", err)
		}
		base, err := url.Parse(rw.config.BaseURL)
		if err != nil {
			return fmt.Errorf("parse base URL: %w", err)
		}
		u.Scheme = base.Scheme
		u.Host = base.Host
		reqURL = u.String()
	}

	// Create HTTP request
	var bodyReader io.Reader
	if len(pkt.Body) > 0 {
		bodyReader = bytes.NewReader(pkt.Body)
	}

	req, err := http.NewRequest(pkt.Method, reqURL, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Copy headers (skip host — net/http sets it)
	for k, v := range pkt.Headers {
		if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
			continue
		}
		for _, val := range v {
			req.Header.Add(k, val)
		}
	}

	// Send request
	resp, err := rw.conn.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body (limit to 1MB)
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	// Store response back on packet
	pkt.Response = &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		Timestamp:  time.Now(),
	}

	// Run assertions
	if rw.config.ValidateResponse && len(rw.config.Assertions) > 0 {
		if err := rw.runAssertions(pkt); err != nil {
			return err
		}
	}

	return nil
}

// runAssertions validates response against configured assertions
func (rw *ReplayWorker) runAssertions(pkt *Packet) error {
	for _, a := range rw.config.Assertions {
		switch a.Type {
		case "status":
			expected, _ := strconv.Atoi(a.Value)
			if pkt.Response.StatusCode != expected {
				return fmt.Errorf("status assertion: expected %d, got %d", expected, pkt.Response.StatusCode)
			}
		case "regex":
			bodyStr := string(pkt.Response.Body)
			matched, _ := regexp.MatchString(a.Value, bodyStr)
			if !matched {
				return fmt.Errorf("regex assertion failed: pattern %s", a.Value)
			}
		case "json_path":
			bodyStr := string(pkt.Response.Body)
			if !strings.Contains(bodyStr, a.Value) {
				return fmt.Errorf("json_path assertion failed: expected %s in response", a.Value)
			}
		case "latency":
			maxMs, _ := strconv.ParseFloat(a.Value, 64)
			for _, lat := range rw.latencies {
				if float64(lat.Milliseconds()) > maxMs {
					return fmt.Errorf("latency assertion: max %sms exceeded", a.Value)
				}
			}
		}
	}
	return nil
}

// GetLatencies returns collected latencies (thread-safe)
func (rw *ReplayWorker) GetLatencies() []time.Duration {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	out := make([]time.Duration, len(rw.latencies))
	copy(out, rw.latencies)
	return out
}

// GetErrors returns collected errors (thread-safe)
func (rw *ReplayWorker) GetErrors() []error {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	out := make([]error, len(rw.errors))
	copy(out, rw.errors)
	return out
}

// --- Replay Engine ----------------------------------------------------------

// ReplayEngine orchestrates multiple workers
type ReplayEngine struct {
	config     *ReplayConfig
	capture    *Capture
	numWorkers int
}

// NewReplayEngine creates a replay engine
func NewReplayEngine(config *ReplayConfig, capture *Capture, numWorkers int) *ReplayEngine {
	if numWorkers <= 0 {
		numWorkers = 1
	}
	return &ReplayEngine{
		config:     config,
		capture:    capture,
		numWorkers: numWorkers,
	}
}

// Run executes the replay and returns results
func (re *ReplayEngine) Run() (*ReplayResult, error) {
	if len(re.capture.Packets) == 0 {
		return nil, fmt.Errorf("no packets to replay")
	}

	// Apply packet filter
	packets := re.capture.Packets
	if re.config.Filter != nil {
		packets = re.capture.Filter(re.config.Filter)
		if len(packets) == 0 {
			return nil, fmt.Errorf("no packets match filter")
		}
	}

	// Split packets among workers
	chunkSize := (len(packets) + re.numWorkers - 1) / re.numWorkers

	result := &ReplayResult{
		Capture:      re.capture,
		Config:       re.config,
		StartTime:    time.Now(),
		TotalPackets: len(packets),
		Errors:       make(map[string]int),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	allLatencies := make([]time.Duration, 0)
	totalSucceeded := 0
	totalFailed := 0

	// Limit concurrency with semaphore
	sem := make(chan struct{}, re.config.MaxConcurrency)

	for w := 0; w < re.numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			start := workerID * chunkSize
			end := start + chunkSize
			if end > len(packets) {
				end = len(packets)
			}
			if start >= len(packets) {
				return
			}

			worker := NewReplayWorker(workerID, re.config, re.capture, packets[start:end])

			if err := worker.Run(); err != nil {
				mu.Lock()
				result.Errors[err.Error()]++
				mu.Unlock()
			}

			workerLats := worker.GetLatencies()
			workerErrs := worker.GetErrors()

			mu.Lock()
			allLatencies = append(allLatencies, workerLats...)
			totalFailed += len(workerErrs)
			totalSucceeded += len(workerLats) - len(workerErrs)
			mu.Unlock()
		}(w)
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.Replayed = len(allLatencies)
	result.Succeeded = totalSucceeded
	result.Failed = totalFailed
	result.Latencies = allLatencies

	// Calculate latency percentiles
	if len(allLatencies) > 0 {
		sort.Slice(allLatencies, func(i, j int) bool { return allLatencies[i] < allLatencies[j] })
		var sum time.Duration
		for _, l := range allLatencies {
			sum += l
		}
		result.AvgLatency = sum / time.Duration(len(allLatencies))
		result.P50Latency = calcPercentile(allLatencies, 50)
		result.P95Latency = calcPercentile(allLatencies, 95)
		result.P99Latency = calcPercentile(allLatencies, 99)
	}

	return result, nil
}

// ExportJSON writes results to JSON file
func (re *ReplayResult) ExportJSONToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(re)
}
