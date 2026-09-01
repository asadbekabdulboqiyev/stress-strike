package replay

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// --- Core Types -------------------------------------------------------------

type Capture struct {
	Source    string
	Format    CaptureFormat
	Packets   []*Packet
	Sessions  map[string]*TLSSession
	TLSKeys   []*TLSKey
	StartTime time.Time
	EndTime   time.Time
	Metadata  map[string]string
	mu        sync.RWMutex
}

type CaptureFormat string

const (
	FormatPCAP CaptureFormat = "pcap"
	FormatHAR  CaptureFormat = "har"
)

type TLSKey struct {
	IP   string
	Port int
	Key  *tls.Certificate
}

type TLSSession struct {
	ClientRandom []byte
	ServerRandom []byte
	MasterSecret []byte
	CipherSuite  uint16
	Key          *TLSKey
}

type Packet struct {
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   int
	DstPort   int
	Protocol  string
	Method    string
	URL       string
	Headers   http.Header
	Body      []byte
	Response  *Response
	StreamID  uint32
	IsRequest bool
}

type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Timestamp  time.Time
	Duration   time.Duration
}

type ReplayConfig struct {
	RateMultiplier   float64
	MaxConcurrency   int
	Duration         time.Duration
	BaseURL          string
	SkipTLSVerify    bool
	TLSKeys          []*TLSKey
	FollowRedirects  bool
	ValidateResponse bool
	Assertions       []Assertion
	OutputReport     bool
	ReportDir        string
	Filter           *PacketFilter
}

type PacketFilter struct {
	Methods     []string
	URLPatterns []string
	StatusCodes []int
	MinLatency  time.Duration
	MaxLatency  time.Duration
	Protocols   []string
	Hosts       []string
}

type Assertion struct {
	Type  string
	Value string
}

type ReplayResult struct {
	Capture      *Capture        `json:"-"`
	Config       *ReplayConfig   `json:"-"`
	StartTime    time.Time       `json:"start_time"`
	EndTime      time.Time       `json:"end_time"`
	TotalPackets int             `json:"total_packets"`
	Replayed     int             `json:"replayed"`
	Succeeded    int             `json:"succeeded"`
	Failed       int             `json:"failed"`
	Errors       map[string]int  `json:"errors"`
	Latencies    []time.Duration `json:"-"`
	AvgLatency   time.Duration   `json:"avg_latency_ms"`
	P50Latency   time.Duration   `json:"p50_latency_ms"`
	P95Latency   time.Duration   `json:"p95_latency_ms"`
	P99Latency   time.Duration   `json:"p99_latency_ms"`
}

// --- Capture Methods --------------------------------------------------------

func (c *Capture) AddPacket(p *Packet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Sessions == nil {
		c.Sessions = make(map[string]*TLSSession)
	}
	if c.Metadata == nil {
		c.Metadata = make(map[string]string)
	}
	c.Packets = append(c.Packets, p)
	if c.StartTime.IsZero() || p.Timestamp.Before(c.StartTime) {
		c.StartTime = p.Timestamp
	}
	if p.Timestamp.After(c.EndTime) {
		c.EndTime = p.Timestamp
	}
}

func (c *Capture) Filter(f *PacketFilter) []*Packet {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*Packet
	for _, p := range c.Packets {
		if matchesFilter(p, f) {
			out = append(out, p)
		}
	}
	return out
}

func (c *Capture) ExportJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}

// --- TLS Helpers ------------------------------------------------------------

func TLSConfigFromKeys(keys []*TLSKey, skipVerify bool) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	}
	if len(keys) > 0 {
		certs := make([]tls.Certificate, 0, len(keys))
		for _, k := range keys {
			if k.Key != nil {
				certs = append(certs, *k.Key)
			}
		}
		cfg.Certificates = certs
	}
	return cfg
}

// --- Filtering Helpers ------------------------------------------------------

func matchesFilter(p *Packet, f *PacketFilter) bool {
	if f == nil {
		return true
	}
	if len(f.Methods) > 0 && !contains(f.Methods, p.Method) {
		return false
	}
	if len(f.Protocols) > 0 && !contains(f.Protocols, p.Protocol) {
		return false
	}
	if len(f.Hosts) > 0 {
		u, _ := url.Parse(p.URL)
		if u != nil && !contains(f.Hosts, u.Host) {
			return false
		}
	}
	if len(f.URLPatterns) > 0 {
		found := false
		for _, pat := range f.URLPatterns {
			if pat == "*" || strings.Contains(p.URL, pat) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if p.Response != nil {
		if len(f.StatusCodes) > 0 && !containsInt(f.StatusCodes, p.Response.StatusCode) {
			return false
		}
		if f.MinLatency > 0 && p.Response.Duration < f.MinLatency {
			return false
		}
		if f.MaxLatency > 0 && p.Response.Duration > f.MaxLatency {
			return false
		}
	}
	return true
}

func contains[T comparable](slice []T, val T) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func calcPercentile(sorted []time.Duration, pct float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)-1) * pct / 100.0)
	return sorted[idx]
}
