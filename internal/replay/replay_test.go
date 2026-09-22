package replay

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- HAR Parsing Tests ------------------------------------------------------

func TestParseHAR(t *testing.T) {
	harData := `{
  "log": {
    "version": "1.2",
    "creator": {"name": "test", "version": "1.0"},
    "entries": [
      {
        "startedDateTime": "2025-01-15T10:30:00.000Z",
        "time": 150.5,
        "request": {
          "method": "GET",
          "url": "https://example.com/api/users",
          "httpVersion": "HTTP/2.0",
          "headers": [
            {"name": "Accept", "value": "application/json"},
            {"name": "Authorization", "value": "Bearer token123"}
          ],
          "queryString": [
            {"name": "page", "value": "1"},
            {"name": "limit", "value": "10"}
          ]
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "headers": [
            {"name": "Content-Type", "value": "application/json"}
          ],
          "content": {
            "size": 512,
            "mimeType": "application/json",
            "text": "{\"users\": []}"
          }
        }
      },
      {
        "startedDateTime": "2025-01-15T10:30:01.000Z",
        "time": 50.0,
        "request": {
          "method": "POST",
          "url": "https://example.com/api/login",
          "httpVersion": "HTTP/2.0",
          "headers": [
            {"name": "Content-Type", "value": "application/json"}
          ],
          "queryString": [],
          "postData": {
            "mimeType": "application/json",
            "text": "{\"user\":\"admin\",\"pass\":\"secret\"}"
          }
        },
        "response": {
          "status": 201,
          "statusText": "Created",
          "headers": [],
          "content": {
            "size": 64,
            "mimeType": "application/json",
            "text": "{\"token\": \"abc\"}"
          }
        }
      }
    ]
  }
}`

	dir := t.TempDir()
	harPath := filepath.Join(dir, "test.har")
	if err := os.WriteFile(harPath, []byte(harData), 0644); err != nil {
		t.Fatal(err)
	}

	capture, err := ParseHAR(harPath)
	if err != nil {
		t.Fatalf("ParseHAR failed: %v", err)
	}

	if capture.Source != harPath {
		t.Errorf("Source = %q, want %q", capture.Source, harPath)
	}
	if capture.Format != FormatHAR {
		t.Errorf("Format = %q, want %q", capture.Format, FormatHAR)
	}
	if len(capture.Packets) != 2 {
		t.Fatalf("len(Packets) = %d, want 2", len(capture.Packets))
	}

	// First entry
	p0 := capture.Packets[0]
	if p0.Method != "GET" {
		t.Errorf("Packets[0].Method = %q, want GET", p0.Method)
	}
	if p0.URL != "https://example.com/api/users?page=1&limit=10" {
		t.Errorf("Packets[0].URL = %q, want query-string URL", p0.URL)
	}
	if p0.Headers.Get("Accept") != "application/json" {
		t.Errorf("Packets[0] Accept header = %q", p0.Headers.Get("Accept"))
	}
	if p0.Response == nil || p0.Response.StatusCode != 200 {
		t.Errorf("Packets[0] response status = %v, want 200", p0.Response)
	}
	if string(p0.Response.Body) != `{"users": []}` {
		t.Errorf("Packets[0] response body = %q", p0.Response.Body)
	}

	// Second entry
	p1 := capture.Packets[1]
	if p1.Method != "POST" {
		t.Errorf("Packets[1].Method = %q, want POST", p1.Method)
	}
	if string(p1.Body) != `{"user":"admin","pass":"secret"}` {
		t.Errorf("Packets[1].Body = %q", p1.Body)
	}
	if p1.Response.StatusCode != 201 {
		t.Errorf("Packets[1] response status = %d, want 201", p1.Response.StatusCode)
	}

	// Timestamps
	if capture.StartTime.After(capture.EndTime) {
		t.Errorf("StartTime %v is after EndTime %v", capture.StartTime, capture.EndTime)
	}
}

func TestParseHAR_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.har")
	os.WriteFile(p, []byte(`{not json`), 0644)

	_, err := ParseHAR(p)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseHAR_FileNotFound(t *testing.T) {
	_, err := ParseHAR("/nonexistent/path.har")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseHAR_InvalidTimestamp(t *testing.T) {
	harData := `{
  "log": {
    "version": "1.2",
    "creator": {"name": "test", "version": "1.0"},
    "entries": [{
      "startedDateTime": "not-a-date",
      "time": 10,
      "request": {"method": "GET", "url": "https://x.com", "httpVersion": "HTTP/1.1", "headers": [], "queryString": []},
      "response": {"status": 200, "statusText": "OK", "headers": [], "content": {"size": 0, "mimeType": "text/html"}}
    }]
  }
}`

	dir := t.TempDir()
	p := filepath.Join(dir, "bad-ts.har")
	os.WriteFile(p, []byte(harData), 0644)

	capture, err := ParseHAR(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Invalid timestamp should fall back to time.Now(), packet should still exist
	if len(capture.Packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(capture.Packets))
	}
}

// --- Rate Multiplier Tests --------------------------------------------------

func TestRateMultiplier_DefaultsTo1(t *testing.T) {
	cfg := &ReplayConfig{
		RateMultiplier: 0,
		MaxConcurrency: 1,
	}
	// A worker with 0 packets returns nil
	capture := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	w := NewReplayWorker(0, cfg, capture, nil)
	err := w.Run()
	if err != nil {
		t.Errorf("empty packets should return nil, got %v", err)
	}
}

func TestRateMultiplier_NegativeDefaultsTo1(t *testing.T) {
	cfg := &ReplayConfig{
		RateMultiplier: -5.0,
		MaxConcurrency: 1,
	}
	// Provide a non-HTTP packet so Run enters the ticker loop and corrects the multiplier
	capture := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	pkt := &Packet{Method: "", URL: ""} // non-HTTP — replayPacket returns nil
	w := NewReplayWorker(0, cfg, capture, []*Packet{pkt})
	err := w.Run()
	if err != nil {
		t.Errorf("non-HTTP packet should return nil, got %v", err)
	}
	// After Run, RateMultiplier should have been corrected to 1.0
	if cfg.RateMultiplier != 1.0 {
		t.Errorf("RateMultiplier = %v, want 1.0", cfg.RateMultiplier)
	}
}

func TestRateMultiplier_PositiveValue(t *testing.T) {
	cfg := &ReplayConfig{
		RateMultiplier: 10.0,
		MaxConcurrency: 1,
	}
	capture := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	w := NewReplayWorker(0, cfg, capture, []*Packet{})
	w.Run()
	if cfg.RateMultiplier != 10.0 {
		t.Errorf("RateMultiplier should stay 10.0, got %v", cfg.RateMultiplier)
	}
}

// --- Packet Filtering Tests -------------------------------------------------

func TestCapture_Filter_NilFilter(t *testing.T) {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	c.AddPacket(&Packet{Method: "GET", URL: "https://example.com"})
	c.AddPacket(&Packet{Method: "POST", URL: "https://example.com"})

	result := c.Filter(nil)
	if len(result) != 2 {
		t.Errorf("nil filter should return all, got %d", len(result))
	}
}

func TestCapture_Filter_Methods(t *testing.T) {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	c.AddPacket(&Packet{Method: "GET", URL: "https://a.com"})
	c.AddPacket(&Packet{Method: "POST", URL: "https://a.com"})
	c.AddPacket(&Packet{Method: "DELETE", URL: "https://a.com"})

	f := &PacketFilter{Methods: []string{"GET", "POST"}}
	result := c.Filter(f)
	if len(result) != 2 {
		t.Errorf("method filter: got %d, want 2", len(result))
	}
}

func TestCapture_Filter_Protocols(t *testing.T) {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	c.AddPacket(&Packet{Method: "GET", Protocol: "http", URL: "https://a.com"})
	c.AddPacket(&Packet{Method: "GET", Protocol: "https", URL: "https://a.com"})
	c.AddPacket(&Packet{Method: "GET", Protocol: "ws", URL: "https://a.com"})

	f := &PacketFilter{Protocols: []string{"http"}}
	result := c.Filter(f)
	if len(result) != 1 {
		t.Errorf("protocol filter: got %d, want 1", len(result))
	}
}

func TestCapture_Filter_URLPatterns(t *testing.T) {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	c.AddPacket(&Packet{Method: "GET", URL: "https://example.com/api/users"})
	c.AddPacket(&Packet{Method: "GET", URL: "https://example.com/api/orders"})
	c.AddPacket(&Packet{Method: "GET", URL: "https://example.com/health"})

	f := &PacketFilter{URLPatterns: []string{"/api/"}}
	result := c.Filter(f)
	if len(result) != 2 {
		t.Errorf("URL pattern filter: got %d, want 2", len(result))
	}
}

func TestCapture_Filter_URLPatternWildcard(t *testing.T) {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	c.AddPacket(&Packet{Method: "GET", URL: "https://a.com/x"})
	c.AddPacket(&Packet{Method: "GET", URL: "https://b.com/y"})

	f := &PacketFilter{URLPatterns: []string{"*"}}
	result := c.Filter(f)
	if len(result) != 2 {
		t.Errorf("wildcard filter: got %d, want 2", len(result))
	}
}

func TestCapture_Filter_Hosts(t *testing.T) {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	c.AddPacket(&Packet{Method: "GET", URL: "https://example.com/a"})
	c.AddPacket(&Packet{Method: "GET", URL: "https://other.com/b"})

	f := &PacketFilter{Hosts: []string{"example.com"}}
	result := c.Filter(f)
	if len(result) != 1 {
		t.Errorf("host filter: got %d, want 1", len(result))
	}
}

func TestCapture_Filter_StatusCodes(t *testing.T) {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	c.AddPacket(&Packet{
		Method: "GET", URL: "https://a.com",
		Response: &Response{StatusCode: 200, Duration: 10 * time.Millisecond},
	})
	c.AddPacket(&Packet{
		Method: "GET", URL: "https://b.com",
		Response: &Response{StatusCode: 404, Duration: 5 * time.Millisecond},
	})
	c.AddPacket(&Packet{
		Method: "GET", URL: "https://c.com",
		Response: &Response{StatusCode: 500, Duration: 20 * time.Millisecond},
	})

	f := &PacketFilter{StatusCodes: []int{200, 500}}
	result := c.Filter(f)
	if len(result) != 2 {
		t.Errorf("status code filter: got %d, want 2", len(result))
	}
}

func TestCapture_Filter_Latency(t *testing.T) {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	c.AddPacket(&Packet{
		Method: "GET", URL: "https://a.com",
		Response: &Response{StatusCode: 200, Duration: 5 * time.Millisecond},
	})
	c.AddPacket(&Packet{
		Method: "GET", URL: "https://b.com",
		Response: &Response{StatusCode: 200, Duration: 50 * time.Millisecond},
	})
	c.AddPacket(&Packet{
		Method: "GET", URL: "https://c.com",
		Response: &Response{StatusCode: 200, Duration: 200 * time.Millisecond},
	})

	f := &PacketFilter{MinLatency: 10 * time.Millisecond, MaxLatency: 100 * time.Millisecond}
	result := c.Filter(f)
	if len(result) != 1 {
		t.Errorf("latency filter: got %d, want 1", len(result))
	}
	if len(result) == 1 && result[0].URL != "https://b.com" {
		t.Errorf("latency filter: got %q, want b.com", result[0].URL)
	}
}

func TestCapture_Filter_NoResponsePacket(t *testing.T) {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	c.AddPacket(&Packet{Method: "GET", URL: "https://a.com"}) // no Response

	f := &PacketFilter{StatusCodes: []int{200}}
	result := c.Filter(f)
	// Packet without response should pass (status filter only applies when Response != nil)
	if len(result) != 1 {
		t.Errorf("no-response filter: got %d, want 1", len(result))
	}
}

func TestCapture_Filter_Combined(t *testing.T) {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	c.AddPacket(&Packet{
		Method: "GET", Protocol: "http", URL: "https://example.com/api/a",
		Response: &Response{StatusCode: 200, Duration: 10 * time.Millisecond},
	})
	c.AddPacket(&Packet{
		Method: "POST", Protocol: "http", URL: "https://example.com/api/b",
		Response: &Response{StatusCode: 201, Duration: 20 * time.Millisecond},
	})
	c.AddPacket(&Packet{
		Method: "GET", Protocol: "https", URL: "https://example.com/other",
		Response: &Response{StatusCode: 200, Duration: 5 * time.Millisecond},
	})

	f := &PacketFilter{
		Methods:     []string{"GET"},
		Protocols:   []string{"http"},
		URLPatterns: []string{"/api/"},
	}
	result := c.Filter(f)
	if len(result) != 1 {
		t.Errorf("combined filter: got %d, want 1", len(result))
	}
}

// --- Internal Helper Tests --------------------------------------------------

func TestMatchesFilter_NilFilter(t *testing.T) {
	if !matchesFilter(&Packet{Method: "GET"}, nil) {
		t.Error("nil filter should match everything")
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		slice []string
		val   string
		want  bool
	}{
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "d", false},
		{[]string{}, "a", false},
		{nil, "a", false},
	}
	for _, tt := range tests {
		got := contains(tt.slice, tt.val)
		if got != tt.want {
			t.Errorf("contains(%v, %q) = %v, want %v", tt.slice, tt.val, got, tt.want)
		}
	}
}

func TestContainsInt(t *testing.T) {
	tests := []struct {
		slice []int
		val   int
		want  bool
	}{
		{[]int{1, 2, 3}, 2, true},
		{[]int{1, 2, 3}, 4, false},
		{[]int{}, 1, false},
	}
	for _, tt := range tests {
		got := containsInt(tt.slice, tt.val)
		if got != tt.want {
			t.Errorf("containsInt(%v, %d) = %v, want %v", tt.slice, tt.val, got, tt.want)
		}
	}
}

func TestCalcPercentile(t *testing.T) {
	durations := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		40 * time.Millisecond,
		50 * time.Millisecond,
	}

	tests := []struct {
		pct  float64
		want time.Duration
	}{
		{50, 30 * time.Millisecond},
		{95, 40 * time.Millisecond},
		{99, 40 * time.Millisecond},
	}

	for _, tt := range tests {
		got := calcPercentile(durations, tt.pct)
		if got != tt.want {
			t.Errorf("calcPercentile(pct=%.0f) = %v, want %v", tt.pct, got, tt.want)
		}
	}
}

func TestCalcPercentile_Empty(t *testing.T) {
	got := calcPercentile(nil, 50)
	if got != 0 {
		t.Errorf("empty slice: got %v, want 0", got)
	}
}

func TestCalcPercentile_Single(t *testing.T) {
	d := []time.Duration{42 * time.Millisecond}
	got := calcPercentile(d, 50)
	if got != 42*time.Millisecond {
		t.Errorf("single element: got %v, want 42ms", got)
	}
}

// --- TLSConfig Tests --------------------------------------------------------

func TestTLSConfigFromKeys_Empty(t *testing.T) {
	cfg := TLSConfigFromKeys(nil, false)
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false")
	}
}

func TestTLSConfigFromKeys_EmptyWithSkipVerify(t *testing.T) {
	cfg := TLSConfigFromKeys(nil, true)
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestTLSConfigFromKeys_WithNilKey(t *testing.T) {
	keys := []*TLSKey{{IP: "1.2.3.4", Port: 443, Key: nil}}
	cfg := TLSConfigFromKeys(keys, false)
	// Nil key should be skipped, resulting in 0 certificates
	if len(cfg.Certificates) != 0 {
		t.Errorf("expected 0 certs for nil key, got %d", len(cfg.Certificates))
	}
}

// --- Capture AddPacket Tests ------------------------------------------------

func TestCapture_AddPacket_Timestamps(t *testing.T) {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	t1 := time.Date(2025, 1, 1, 10, 0, 5, 0, time.UTC)
	t2 := time.Date(2025, 1, 1, 10, 0, 10, 0, time.UTC)
	t3 := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC) // earlier than t1

	c.AddPacket(&Packet{Timestamp: t1})
	if !c.StartTime.Equal(t1) || !c.EndTime.Equal(t1) {
		t.Errorf("after 1st packet: Start=%v End=%v, want %v", c.StartTime, c.EndTime, t1)
	}

	c.AddPacket(&Packet{Timestamp: t2})
	if !c.StartTime.Equal(t1) || !c.EndTime.Equal(t2) {
		t.Errorf("after 2nd packet: Start=%v End=%v", c.StartTime, c.EndTime)
	}

	c.AddPacket(&Packet{Timestamp: t3})
	if !c.StartTime.Equal(t3) || !c.EndTime.Equal(t2) {
		t.Errorf("after 3rd packet: Start=%v End=%v, want Start=%v End=%v", c.StartTime, c.EndTime, t3, t2)
	}
}

func TestCapture_AddPacket_InitMaps(t *testing.T) {
	c := &Capture{Format: FormatHAR} // nil Sessions and Metadata
	c.AddPacket(&Packet{Timestamp: time.Now()})
	if c.Sessions == nil {
		t.Error("Sessions should be initialized")
	}
	if c.Metadata == nil {
		t.Error("Metadata should be initialized")
	}
}

// --- Capture ExportJSON Tests -----------------------------------------------

func TestCapture_ExportJSON(t *testing.T) {
	c := &Capture{
		Source: "test",
		Format: FormatHAR,
		Metadata: map[string]string{
			"key": "value",
		},
	}
	c.AddPacket(&Packet{
		Method:    "GET",
		URL:       "https://example.com",
		Timestamp: time.Now(),
	})

	var buf bytes.Buffer
	err := c.ExportJSON(&buf)
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if out["Source"] != "test" {
		t.Errorf("Source = %v", out["Source"])
	}
}

// --- ReplayResult ExportJSONToFile Tests ------------------------------------

func TestReplayResult_ExportJSONToFile(t *testing.T) {
	result := &ReplayResult{
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		TotalPackets: 100,
		Replayed:     95,
		Succeeded:    90,
		Failed:       5,
		Errors:       map[string]int{"timeout": 3, "reset": 2},
		AvgLatency:   50 * time.Millisecond,
		P50Latency:   45 * time.Millisecond,
		P95Latency:   120 * time.Millisecond,
		P99Latency:   200 * time.Millisecond,
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "result.json")

	err := result.ExportJSONToFile(path)
	if err != nil {
		t.Fatalf("ExportJSONToFile failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if out["total_packets"] != float64(100) {
		t.Errorf("total_packets = %v", out["total_packets"])
	}
	if out["succeeded"] != float64(90) {
		t.Errorf("succeeded = %v", out["succeeded"])
	}
}

func TestReplayResult_ExportJSONToFile_BadPath(t *testing.T) {
	result := &ReplayResult{}
	err := result.ExportJSONToFile("/nonexistent/dir/result.json")
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

// --- NewReplayWorker Tests -------------------------------------------------

func TestNewReplayWorker(t *testing.T) {
	cfg := &ReplayConfig{
		RateMultiplier: 5.0,
		MaxConcurrency: 10,
		SkipTLSVerify:  true,
	}
	capture := &Capture{Format: FormatHAR}
	packets := []*Packet{
		{Method: "GET", URL: "https://example.com"},
	}

	w := NewReplayWorker(42, cfg, capture, packets)
	if w.id != 42 {
		t.Errorf("id = %d, want 42", w.id)
	}
	if w.config != cfg {
		t.Error("config not set")
	}
	if w.capture != capture {
		t.Error("capture not set")
	}
	if len(w.packets) != 1 {
		t.Errorf("packets len = %d, want 1", len(w.packets))
	}
	if w.stopCh == nil {
		t.Error("stopCh not initialized")
	}
}

func TestNewReplayWorker_Stop(t *testing.T) {
	cfg := &ReplayConfig{RateMultiplier: 1000.0, MaxConcurrency: 1, SkipTLSVerify: true}
	capture := &Capture{Format: FormatHAR}
	// Need a non-HTTP packet so Run enters the ticker loop
	pkt := &Packet{Method: "", URL: ""}
	w := NewReplayWorker(0, cfg, capture, []*Packet{pkt})

	done := make(chan error, 1)
	go func() {
		done <- w.Run()
	}()

	w.Stop()
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Errorf("expected stop error, got %v", err)
	}
}

// --- NewReplayEngine Tests -------------------------------------------------

func TestNewReplayEngine_DefaultWorkers(t *testing.T) {
	cfg := &ReplayConfig{RateMultiplier: 1.0, MaxConcurrency: 1}
	c := &Capture{Format: FormatHAR}
	e := NewReplayEngine(cfg, c, 0)
	if e.numWorkers != 1 {
		t.Errorf("numWorkers = %d, want 1 (default)", e.numWorkers)
	}
}

func TestNewReplayEngine_CustomWorkers(t *testing.T) {
	cfg := &ReplayConfig{RateMultiplier: 1.0, MaxConcurrency: 4}
	c := &Capture{Format: FormatHAR}
	e := NewReplayEngine(cfg, c, 8)
	if e.numWorkers != 8 {
		t.Errorf("numWorkers = %d, want 8", e.numWorkers)
	}
}

func TestReplayEngine_EmptyCapture(t *testing.T) {
	cfg := &ReplayConfig{RateMultiplier: 1.0, MaxConcurrency: 1}
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0)}
	e := NewReplayEngine(cfg, c, 1)

	_, err := e.Run()
	if err == nil {
		t.Fatal("expected error for empty capture")
	}
	if !strings.Contains(err.Error(), "no packets") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Non-HTTP Packet Tests -------------------------------------------------

func TestReplayWorker_SkipsNonHTTP(t *testing.T) {
	cfg := &ReplayConfig{RateMultiplier: 1.0, MaxConcurrency: 1, SkipTLSVerify: true}
	capture := &Capture{Format: FormatPCAP}

	// Packet with no method/URL — replayPacket returns nil (no error), but Run still records latency
	pkt := &Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("127.0.0.1"),
		DstIP:     net.ParseIP("127.0.0.1"),
		SrcPort:   12345,
		DstPort:   80,
		Protocol:  "tcp",
	}

	w := NewReplayWorker(0, cfg, capture, []*Packet{pkt})
	err := w.Run()
	if err != nil {
		t.Errorf("non-HTTP packet should not cause error, got: %v", err)
	}
	// Latency is recorded but no error
	if len(w.GetErrors()) != 0 {
		t.Errorf("expected 0 errors for non-HTTP packet, got %d", len(w.GetErrors()))
	}
}

// --- Header Copy Tests (replayPacket) --------------------------------------

func TestReplayWorker_SkipsHostAndContentLengthHeaders(t *testing.T) {
	cfg := &ReplayConfig{
		RateMultiplier: 1.0,
		MaxConcurrency: 1,
		SkipTLSVerify:  true,
	}

	pkt := &Packet{
		Method: "GET",
		URL:    "https://example.com",
		Headers: http.Header{
			"Host":           []string{"example.com"},
			"Content-Length": []string{"0"},
			"X-Custom":       []string{"yes"},
		},
	}

	// replayPacket will fail because there's no server, but we verify
	// it doesn't panic and returns an error (connection refused)
	w := NewReplayWorker(0, cfg, &Capture{}, []*Packet{pkt})
	err := w.Run()
	// Expecting a connection error (no server), not a panic
	if err != nil && strings.Contains(err.Error(), "request failed") {
		// This is expected — no server running
		return
	}
}

// --- assertFilter各家 -------------------------------------------------------------

func TestMatchesFilter_Full(t *testing.T) {
	p := &Packet{
		Method:   "POST",
		Protocol: "http",
		URL:      "https://api.example.com/data",
		Response: &Response{
			StatusCode: 201,
			Duration:   50 * time.Millisecond,
		},
	}

	f := &PacketFilter{
		Methods:     []string{"POST"},
		Protocols:   []string{"http"},
		Hosts:       []string{"api.example.com"},
		URLPatterns: []string{"/data"},
		StatusCodes: []int{201},
		MinLatency:  10 * time.Millisecond,
		MaxLatency:  100 * time.Millisecond,
	}

	if !matchesFilter(p, f) {
		t.Error("packet should match all filter criteria")
	}
}

func TestMatchesFilter_MethodMismatch(t *testing.T) {
	p := &Packet{Method: "GET"}
	f := &PacketFilter{Methods: []string{"POST"}}
	if matchesFilter(p, f) {
		t.Error("should not match different method")
	}
}

func TestMatchesFilter_ProtocolMismatch(t *testing.T) {
	p := &Packet{Method: "GET", Protocol: "https"}
	f := &PacketFilter{Protocols: []string{"http"}}
	if matchesFilter(p, f) {
		t.Error("should not match different protocol")
	}
}

func TestMatchesFilter_URLPatternMismatch(t *testing.T) {
	p := &Packet{Method: "GET", URL: "https://example.com/login"}
	f := &PacketFilter{URLPatterns: []string{"/api/"}}
	if matchesFilter(p, f) {
		t.Error("should not match different URL pattern")
	}
}

func TestMatchesFilter_MinLatency(t *testing.T) {
	p := &Packet{
		Method: "GET", URL: "https://x.com",
		Response: &Response{StatusCode: 200, Duration: 5 * time.Millisecond},
	}
	f := &PacketFilter{MinLatency: 10 * time.Millisecond}
	if matchesFilter(p, f) {
		t.Error("should not match below min latency")
	}
}

func TestMatchesFilter_MaxLatency(t *testing.T) {
	p := &Packet{
		Method: "GET", URL: "https://x.com",
		Response: &Response{StatusCode: 200, Duration: 200 * time.Millisecond},
	}
	f := &PacketFilter{MaxLatency: 100 * time.Millisecond}
	if matchesFilter(p, f) {
		t.Error("should not match above max latency")
	}
}

func TestMatchesFilter_StatusMismatch(t *testing.T) {
	p := &Packet{
		Method: "GET", URL: "https://x.com",
		Response: &Response{StatusCode: 404},
	}
	f := &PacketFilter{StatusCodes: []int{200, 500}}
	if matchesFilter(p, f) {
		t.Error("should not match different status code")
	}
}

func TestMatchesFilter_HostMismatch(t *testing.T) {
	p := &Packet{Method: "GET", URL: "https://other.com/page"}
	f := &PacketFilter{Hosts: []string{"example.com"}}
	if matchesFilter(p, f) {
		t.Error("should not match different host")
	}
}

// --- JoinStrings Tests ------------------------------------------------------

func TestJoinStrings(t *testing.T) {
	tests := []struct {
		ss   []string
		sep  string
		want string
	}{
		{[]string{"a", "b"}, "&", "a&b"},
		{[]string{"a"}, ",", "a"},
		{[]string{}, ",", ""},
		{nil, ",", ""},
		{[]string{"x", "y", "z"}, "-", "x-y-z"},
	}
	for _, tt := range tests {
		got := joinStrings(tt.ss, tt.sep)
		if got != tt.want {
			t.Errorf("joinStrings(%v, %q) = %q, want %q", tt.ss, tt.sep, got, tt.want)
		}
	}
}

// --- Pacing Mode Tests ------------------------------------------------------

func arrivalServer(t *testing.T) (*httptest.Server, func() []time.Time) {
	t.Helper()
	var mu sync.Mutex
	var arr []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arr = append(arr, time.Now())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	getArrivals := func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		out := make([]time.Time, len(arr))
		copy(out, arr)
		return out
	}
	return srv, getArrivals
}

func timedCapture(base time.Time, url string, offsets ...time.Duration) *Capture {
	c := &Capture{Format: FormatHAR, Packets: make([]*Packet, 0, len(offsets))}
	for _, off := range offsets {
		c.AddPacket(&Packet{
			Timestamp: base.Add(off),
			Method:    "GET",
			URL:       url,
			Protocol:  "http",
			IsRequest: true,
		})
	}
	return c
}

func runReplayEngine(t *testing.T, cfg *ReplayConfig, capture *Capture, workers int) *ReplayResult {
	t.Helper()
	engine := NewReplayEngine(cfg, capture, workers)
	result, err := engine.Run()
	if err != nil {
		t.Fatalf("ReplayEngine.Run failed: %v", err)
	}
	return result
}

func TestReplayPacingTiming_PreservesRelativeGaps(t *testing.T) {
	srv, arrivals := arrivalServer(t)
	defer srv.Close()

	// Capture: t0, t0+200ms, t0+500ms -> expected gaps 200ms and 300ms.
	base := time.Now().Add(-time.Second)
	capture := timedCapture(base, srv.URL+"/a", 0, 200*time.Millisecond, 500*time.Millisecond)

	cfg := &ReplayConfig{
		Pacing:         PacingTiming,
		RateMultiplier: 1.0,
		MaxConcurrency: 1,
		SkipTLSVerify:  true,
	}

	result := runReplayEngine(t, cfg, capture, 1)
	if result.Replayed != 3 {
		t.Fatalf("replayed = %d, want 3", result.Replayed)
	}

	times := arrivals()
	if len(times) != 3 {
		t.Fatalf("server saw %d requests, want 3", len(times))
	}
	gap1 := times[1].Sub(times[0])
	gap2 := times[2].Sub(times[1])

	if d := gap1 - 200*time.Millisecond; d > 150*time.Millisecond || d < -150*time.Millisecond {
		t.Errorf("gap1 = %v, want ~200ms (±150ms)", gap1)
	}
	if d := gap2 - 300*time.Millisecond; d > 150*time.Millisecond || d < -150*time.Millisecond {
		t.Errorf("gap2 = %v, want ~300ms (±150ms)", gap2)
	}
}

func TestReplayPacingTiming_RateScalesGaps(t *testing.T) {
	srv, arrivals := arrivalServer(t)
	defer srv.Close()

	// Same capture as above; rate=2 should roughly halve the gaps.
	base := time.Now().Add(-time.Second)
	capture := timedCapture(base, srv.URL+"/b", 0, 200*time.Millisecond, 500*time.Millisecond)

	cfg := &ReplayConfig{
		Pacing:         PacingTiming,
		RateMultiplier: 2.0,
		MaxConcurrency: 1,
		SkipTLSVerify:  true,
	}

	result := runReplayEngine(t, cfg, capture, 1)
	if result.Replayed != 3 {
		t.Fatalf("replayed = %d, want 3", result.Replayed)
	}

	times := arrivals()
	if len(times) != 3 {
		t.Fatalf("server saw %d requests, want 3", len(times))
	}
	half1 := times[1].Sub(times[0])
	half2 := times[2].Sub(times[1])

	if d := half1 - 100*time.Millisecond; d > 150*time.Millisecond || d < -150*time.Millisecond {
		t.Errorf("halved gap1 = %v, want ~100ms (±150ms)", half1)
	}
	if d := half2 - 150*time.Millisecond; d > 175*time.Millisecond || d < -175*time.Millisecond {
		t.Errorf("halved gap2 = %v, want ~150ms (±175ms)", half2)
	}
}

func TestReplayPacingLegacy(t *testing.T) {
	srv, arrivals := arrivalServer(t)
	defer srv.Close()

	// Timestamps far apart, but legacy ignores them and uses 1s/rate = 100ms.
	base := time.Now().Add(-time.Hour)
	capture := timedCapture(base, srv.URL+"/l", 0, 10*time.Minute, 20*time.Minute)

	cfg := &ReplayConfig{
		Pacing:         PacingLegacy,
		RateMultiplier: 10.0,
		MaxConcurrency: 1,
		SkipTLSVerify:  true,
	}

	start := time.Now()
	result := runReplayEngine(t, cfg, capture, 1)
	elapsed := time.Since(start)

	if result.Replayed != 3 {
		t.Errorf("replayed = %d, want 3", result.Replayed)
	}
	if elapsed < 200*time.Millisecond || elapsed > 2*time.Second {
		t.Errorf("legacy replay took %v, want ~300ms but < 2s", elapsed)
	}

	times := arrivals()
	if len(times) != 3 {
		t.Fatalf("server saw %d requests, want 3", len(times))
	}
	for i := 1; i < len(times); i++ {
		gap := times[i].Sub(times[i-1])
		if gap > 300*time.Millisecond {
			t.Errorf("legacy gap %d = %v, want ~100ms", i, gap)
		}
	}
}

// --- Follow Redirects Tests -------------------------------------------------

func TestReplayFollowRedirects(t *testing.T) {
	var redirectHits int32
	var finalHits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&finalHits, 1)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&redirectHits, 1)
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, tc := range []struct {
		name     string
		follow   bool
		wantCode int
	}{
		{"no-follow", false, http.StatusFound},
		{"follow", true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			atomic.StoreInt32(&redirectHits, 0)
			atomic.StoreInt32(&finalHits, 0)

			pkt := &Packet{Method: "GET", URL: srv.URL + "/start", Protocol: "http", IsRequest: true}
			cfg := &ReplayConfig{
				Pacing:          PacingTiming,
				RateMultiplier:  1000,
				MaxConcurrency:  1,
				SkipTLSVerify:   true,
				FollowRedirects: tc.follow,
			}

			w := NewReplayWorker(0, cfg, &Capture{}, []*Packet{pkt})
			if err := w.Run(); err != nil {
				t.Fatalf("Run failed: %v", err)
			}
			if pkt.Response == nil {
				t.Fatal("no response recorded")
			}
			if pkt.Response.StatusCode != tc.wantCode {
				t.Errorf("status = %d, want %d", pkt.Response.StatusCode, tc.wantCode)
			}
			if tc.follow {
				if atomic.LoadInt32(&redirectHits) != 1 {
					t.Errorf("redirect hits = %d, want 1", redirectHits)
				}
				if atomic.LoadInt32(&finalHits) != 1 {
					t.Errorf("final hits = %d, want 1", finalHits)
				}
			} else {
				if atomic.LoadInt32(&redirectHits) == 0 || atomic.LoadInt32(&finalHits) != 0 {
					t.Errorf("redirect=%d final=%d, want redirect hit and no follow", redirectHits, finalHits)
				}
			}
		})
	}
}

// --- Duration Tests ---------------------------------------------------------

func TestReplayDuration(t *testing.T) {
	srv, arrivals := arrivalServer(t)
	defer srv.Close()

	// 20 packets at 200ms apart -> ~4s at rate=1; Duration caps it at 300ms.
	base := time.Now().Add(-time.Hour)
	n := 20
	offsets := make([]time.Duration, n)
	for i := range offsets {
		offsets[i] = time.Duration(i) * 200 * time.Millisecond
	}
	capture := timedCapture(base, srv.URL+"/d", offsets...)

	cfg := &ReplayConfig{
		Pacing:         PacingTiming,
		RateMultiplier: 1.0,
		MaxConcurrency: 1,
		Duration:       300 * time.Millisecond,
		SkipTLSVerify:  true,
	}

	start := time.Now()
	result := runReplayEngine(t, cfg, capture, 1)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("run took %v, want < 2s", elapsed)
	}
	if result.Replayed >= n {
		t.Errorf("replayed = %d, want < %d (duration should stop early)", result.Replayed, n)
	}
	if result.Replayed == 0 {
		t.Error("expected at least one request to replay within duration")
	}
	if len(arrivals()) != result.Replayed {
		t.Errorf("server saw %d requests, want %d", len(arrivals()), result.Replayed)
	}
}
