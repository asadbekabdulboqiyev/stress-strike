// Package prom provides a minimal Prometheus metrics handler registration
// helper. It returns an http.HandlerFunc for /metrics.
package prom

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// Metrics holds minimal counters/gauges.
type Metrics struct {
	requests uint64
	errors   uint64
	latency  uint64 // sum in microseconds (for naive average)
}

// NewMetrics returns a new Metrics instance.
func NewMetrics() *Metrics { return &Metrics{} }

// IncRequests increments request counter.
func (m *Metrics) IncRequests() { atomic.AddUint64(&m.requests, 1) }

// IncErrors increments error counter.
func (m *Metrics) IncErrors() { atomic.AddUint64(&m.errors, 1) }

// ObserveLatency observes latency.
func (m *Metrics) ObserveLatency(d time.Duration) {
	atomic.AddUint64(&m.latency, uint64(d.Microseconds()))
}

// Handler returns an HTTP handler exposing metrics in a minimal text format.
// This is intentionally simple (not full Prometheus exposition) but useful.
func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		reqs := atomic.LoadUint64(&m.requests)
		errs := atomic.LoadUint64(&m.errors)
		lat := atomic.LoadUint64(&m.latency)
		avg := float64(0)
		if reqs > 0 {
			avg = float64(lat) / float64(reqs)
		}
		_, _ = fmt.Fprintf(w, "# HELP ss_requests_total Total requests\n")
		_, _ = fmt.Fprintf(w, "# TYPE ss_requests_total counter\n")
		_, _ = fmt.Fprintf(w, "ss_requests_total %d\n", reqs)
		_, _ = fmt.Fprintf(w, "# HELP ss_errors_total Total errors\n")
		_, _ = fmt.Fprintf(w, "# TYPE ss_errors_total counter\n")
		_, _ = fmt.Fprintf(w, "ss_errors_total %d\n", errs)
		_, _ = fmt.Fprintf(w, "# HELP ss_latency_avg_us Average latency in microseconds\n")
		_, _ = fmt.Fprintf(w, "# TYPE ss_latency_avg_us gauge\n")
		_, _ = fmt.Fprintf(w, "ss_latency_avg_us %s\n", strconv.FormatFloat(avg, 'f', 2, 64))
	}
}
