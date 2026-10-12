// Package prom renders stress-strike run telemetry in the Prometheus text
// exposition format (version 0.0.4), which OpenMetrics scrapers also accept.
//
// The exporter is dependency-free (standard library + internal/metrics) and
// deterministic: every metric family is emitted exactly once, in a fixed order,
// with HELP/TYPE headers, and status codes, error names and step names are
// sorted. The same telemetry snapshot therefore always renders byte-for-byte
// the same document.
//
// # Series layout
//
// Run-wide aggregates carry no labels:
//
//	ss_requests_total                     counter
//	ss_errors_total                       counter
//	ss_status_codes_total{code="..."}     counter (sorted by code)
//	ss_errors_by_name_total{error="..."}  counter (sorted by error name)
//	ss_request_duration_seconds           histogram
//	ss_rps                                gauge
//	ss_active_users                       gauge
//	ss_peak_users                         gauge
//	ss_error_rate                         gauge (0 when there are no requests)
//	ss_uptime_seconds                     gauge
//
// Per-step counters add the step label (sorted by step):
//
//	ss_step_requests_total{step="..."}
//	ss_step_errors_total{step="..."}
//
// # Aggregate source
//
// The unlabelled series come from Telemetry.Overall, the run-wide step the
// engine updates on every iteration, and the histogram is Overall's latency
// distribution. The per-step series come from Telemetry.Steps. Taking all of
// the run-wide numbers from Overall keeps ss_requests_total, the histogram
// _count and the sum of the per-step counters mutually consistent.
//
// # Histogram buckets
//
// internal/metrics uses an HDR-style log-linear histogram with 31744 buckets.
// CumulativeBuckets returns them already folded into cumulative counts with
// inclusive upper bounds, so they are rendered as-is -- every bucket is
// emitted -- and the implicit +Inf bucket is appended carrying the total
// count. _sum and _count are exact.
//
// Emitting all 31744 buckets makes a scraped document large (~1.7 MB for a run
// with observations). Prometheus does not require every `le` boundary, only
// that present buckets are non-decreasing and `le="+Inf"` equals _count, so a
// deployment that cares about scrape size can emit just the boundaries whose
// cumulative count changes without losing any counting accuracy.
//
// # Entry points
//
// Exporter is the scrape target for a run: New attaches a *metrics.Telemetry
// and Handler serves it over HTTP. Metrics is the backward-compatible target
// that carries its own counters (NewMetrics / IncRequests / IncErrors /
// ObserveLatency); FromTelemetry also lets it export a run. Write renders a
// telemetry straight into any io.Writer.
//
// A nil telemetry is always tolerated and renders an all-zero document.
package prom

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
)

// ContentType is the Content-Type served by the handlers and expected by
// Prometheus/OpenMetrics scrapers for this exposition format.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Metric family names, shared by the renderer and the tests.
const (
	metricRequests     = "ss_requests_total"
	metricErrors       = "ss_errors_total"
	metricStatusCodes  = "ss_status_codes_total"
	metricErrorsByName = "ss_errors_by_name_total"
	metricDuration     = "ss_request_duration_seconds"
	metricStepRequests = "ss_step_requests_total"
	metricStepErrors   = "ss_step_errors_total"
)

// selfStepName labels the synthetic step used by Metrics' own counters.
const selfStepName = "self"

// Metrics is the backward-compatible scrape target. The zero value and
// NewMetrics export the instance's own counters (under the synthetic step
// "self"); a Metrics built with FromTelemetry exports a run's telemetry
// instead. It is safe for concurrent use.
type Metrics struct {
	telemetry *metrics.Telemetry
	start     time.Time

	requests atomic.Uint64
	errors   atomic.Uint64
	latency  metrics.Histogram
}

// NewMetrics returns an empty Metrics that exports only its own counters.
func NewMetrics() *Metrics { return &Metrics{start: time.Now()} }

// FromTelemetry returns a Metrics that exports the given run telemetry. A nil
// telemetry is tolerated and yields an all-zero document.
func FromTelemetry(t *metrics.Telemetry) *Metrics {
	return &Metrics{telemetry: t, start: time.Now()}
}

// IncRequests increments the request counter.
func (m *Metrics) IncRequests() { m.requests.Add(1) }

// IncRequestsN increments the request counter by n (used to mirror run
// telemetry deltas without one atomic add per request).
func (m *Metrics) IncRequestsN(n uint64) { m.requests.Add(n) }

// IncErrors increments the error counter. The error is reported under the name
// "unknown", since this compatibility counter does not carry error names.
func (m *Metrics) IncErrors() { m.errors.Add(1) }

// IncErrorsN increments the error counter by n (see IncRequestsN).
func (m *Metrics) IncErrorsN(n uint64) { m.errors.Add(n) }

// ObserveLatency records one latency observation. Negative durations are
// clamped to zero by the histogram.
func (m *Metrics) ObserveLatency(d time.Duration) { m.latency.Add(d) }

// Handler returns an http.HandlerFunc that serves the exposition over HTTP. It
// answers GET only (405 otherwise) and tolerates a nil telemetry.
func (m *Metrics) Handler() http.HandlerFunc { return handler(m.report) }

func (m *Metrics) report() report {
	if t := m.telemetry; t != nil {
		return reportFromTelemetry(t)
	}
	return m.selfReport()
}

func (m *Metrics) selfReport() report {
	reqs := m.requests.Load()
	errs := m.errors.Load()

	var uptime float64
	if !m.start.IsZero() {
		uptime = time.Since(m.start).Seconds()
	}

	rep := report{
		requests:     reqs,
		errors:       errs,
		uptime:       uptime,
		steps:        []stepReport{{name: selfStepName, requests: reqs, errors: errs}},
		errorsByName: selfErrors(errs),
	}
	if reqs > 0 {
		rep.errorRate = float64(errs) / float64(reqs)
	}
	if uptime > 0 {
		rep.rps = float64(reqs) / uptime
	}
	snap := m.latency.Snapshot()
	rep.histCount = snap.Count
	rep.histSum = snap.Sum
	rep.buckets = snap.CumulativeBuckets()
	return rep
}

func selfErrors(n uint64) map[string]uint64 {
	if n == 0 {
		return nil
	}
	return map[string]uint64{"unknown": n}
}

// Exporter renders a *metrics.Telemetry as Prometheus text exposition. It is
// safe for concurrent use and tolerates a nil telemetry.
type Exporter struct {
	telemetry *metrics.Telemetry
}

// New returns an Exporter for t. A nil t renders an all-zero document.
func New(t *metrics.Telemetry) *Exporter { return &Exporter{telemetry: t} }

// Handler returns an http.HandlerFunc that serves the exposition over HTTP. It
// answers GET only (405 otherwise).
func (e *Exporter) Handler() http.HandlerFunc { return handler(e.report) }

func (e *Exporter) report() report { return reportFromTelemetry(e.telemetry) }

// WriteTo renders the exposition into w and returns the number of bytes
// written, implementing io.WriterTo. The signature (rather than the
// error-only one a "WriteTo" might suggest) is deliberate: go vet's stdmethods
// check requires a method named WriteTo to match io.WriterTo, so the error-only
// convenience form lives in Render.
func (e *Exporter) WriteTo(w io.Writer) (int64, error) {
	return renderTo(w, e.report())
}

// Render renders the exposition into w. It is the error-only counterpart to
// WriteTo, which returns the byte count to satisfy io.WriterTo.
func (e *Exporter) Render(w io.Writer) error {
	_, err := renderTo(w, e.report())
	return err
}

// Write renders t as Prometheus text exposition into w. A nil t renders an
// all-zero document.
func Write(w io.Writer, t *metrics.Telemetry) error {
	_, err := renderTo(w, reportFromTelemetry(t))
	return err
}

// Ensure Exporter keeps satisfying io.WriterTo.
var _ io.WriterTo = (*Exporter)(nil)

// --- report model (decoupled from metrics so rendering stays pure) ----------

type report struct {
	requests uint64
	errors   uint64

	statusCodes  map[int]uint64
	errorsByName map[string]uint64

	buckets   []metrics.Bucket
	histSum   uint64 // nanoseconds
	histCount uint64

	rps         float64
	activeUsers int64
	peakUsers   int64
	errorRate   float64
	uptime      float64

	steps []stepReport
}

type stepReport struct {
	name     string
	requests uint64
	errors   uint64
}

func reportFromTelemetry(t *metrics.Telemetry) report {
	if t == nil {
		return report{}
	}

	var uptime float64
	if !t.Start.IsZero() {
		if d := t.Elapsed().Seconds(); d > 0 {
			uptime = d
		}
	}

	rep := report{
		rps:         t.RPS(),
		activeUsers: t.ActiveUsers.Load(),
		peakUsers:   t.PeakUsers.Load(),
		uptime:      uptime,
	}

	if s := t.Overall; s != nil {
		rep.requests = s.Requests()
		rep.errors = s.ErrorCount()
		rep.statusCodes = s.StatusCodes()
		rep.errorsByName = s.Errors()
		if s.Latency != nil {
			snap := s.Latency.Snapshot()
			rep.histCount = snap.Count
			rep.histSum = snap.Sum
			rep.buckets = snap.CumulativeBuckets()
		}
	}
	if rep.requests > 0 {
		rep.errorRate = float64(rep.errors) / float64(rep.requests)
	}
	rep.steps = collectSteps(t)
	return rep
}

// collectSteps merges the per-step stats by name (so duplicate names cannot
// produce duplicate series) and returns them sorted by name.
func collectSteps(t *metrics.Telemetry) []stepReport {
	if len(t.Steps) == 0 {
		return nil
	}
	byName := make(map[string]stepReport, len(t.Steps))
	for _, s := range t.Steps {
		if s == nil {
			continue
		}
		cur := byName[s.Name]
		cur.name = s.Name
		cur.requests += s.Requests()
		cur.errors += s.ErrorCount()
		byName[s.Name] = cur
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]stepReport, 0, len(names))
	for _, name := range names {
		out = append(out, byName[name])
	}
	return out
}

// --- rendering --------------------------------------------------------------

func renderTo(w io.Writer, rep report) (int64, error) {
	var buf bytes.Buffer
	writeReport(&buf, rep)
	return buf.WriteTo(w)
}

func handler(reportFn func() report) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var buf bytes.Buffer
		writeReport(&buf, reportFn())
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}
}

func writeReport(w io.Writer, rep report) {
	p := &printer{w: w}
	writeRequests(p, rep)
	writeErrors(p, rep)
	writeStatusCodes(p, rep)
	writeErrorsByName(p, rep)
	writeHistogram(p, rep)
	writeGauge(p, "ss_rps", "Current request throughput (requests per second).", rep.rps)
	writeGauge(p, "ss_active_users", "Number of currently active virtual users.", float64(rep.activeUsers))
	writeGauge(p, "ss_peak_users", "Peak number of concurrent active virtual users.", float64(rep.peakUsers))
	writeGauge(p, "ss_error_rate", "Fraction of requests that errored (errors/requests); 0 when there are no requests.", rep.errorRate)
	writeGauge(p, "ss_uptime_seconds", "Seconds elapsed since the run started.", rep.uptime)
	writeSteps(p, rep.steps)
}

func writeRequests(p *printer, rep report) {
	p.help(metricRequests, "Total number of requests observed.")
	p.typ(metricRequests, "counter")
	p.line("%s %d\n", metricRequests, rep.requests)
}

func writeErrors(p *printer, rep report) {
	p.help(metricErrors, "Total number of errored requests.")
	p.typ(metricErrors, "counter")
	p.line("%s %d\n", metricErrors, rep.errors)
}

func writeStatusCodes(p *printer, rep report) {
	p.help(metricStatusCodes, "Total number of responses, by HTTP status code.")
	p.typ(metricStatusCodes, "counter")
	for _, code := range metrics.SortedStatusCodes(rep.statusCodes) {
		p.line("%s{code=%s} %d\n", metricStatusCodes, label(strconv.Itoa(code)), rep.statusCodes[code])
	}
}

func writeErrorsByName(p *printer, rep report) {
	p.help(metricErrorsByName, "Total number of errored requests, by error name.")
	p.typ(metricErrorsByName, "counter")
	for _, name := range metrics.SortedErrors(rep.errorsByName) {
		p.line("%s{error=%s} %d\n", metricErrorsByName, label(name), rep.errorsByName[name])
	}
}

func writeHistogram(p *printer, rep report) {
	p.help(metricDuration, "Request latency distribution in seconds, from the run-wide histogram (cumulative buckets, inclusive upper bounds).")
	p.typ(metricDuration, "histogram")
	for _, b := range rep.buckets {
		p.line("%s_bucket{le=\"%s\"} %d\n", metricDuration, formatSeconds(b.UpperBound), b.Count)
	}
	p.line("%s_bucket{le=\"+Inf\"} %d\n", metricDuration, rep.histCount)
	p.line("%s_sum %s\n", metricDuration, formatSeconds(time.Duration(rep.histSum))) //nolint:gosec // nanosecond sum fits int64
	p.line("%s_count %d\n", metricDuration, rep.histCount)
}

func writeSteps(p *printer, steps []stepReport) {
	p.help(metricStepRequests, "Total number of requests observed, per scenario step.")
	p.typ(metricStepRequests, "counter")
	for _, s := range steps {
		p.line("%s{step=%s} %d\n", metricStepRequests, label(s.name), s.requests)
	}

	p.help(metricStepErrors, "Total number of errored requests, per scenario step.")
	p.typ(metricStepErrors, "counter")
	for _, s := range steps {
		p.line("%s{step=%s} %d\n", metricStepErrors, label(s.name), s.errors)
	}
}

func writeGauge(p *printer, name, help string, v float64) {
	p.help(name, help)
	p.typ(name, "gauge")
	p.line("%s %s\n", name, formatFloat(v))
}

// printer writes exposition lines. Write errors are intentionally ignored: the
// whole document is rendered into an in-memory buffer before it reaches the
// caller, so a bytes.Buffer never short-writes and any error on the final
// Write is reported by Write/WriteTo/Render/Handler.
type printer struct{ w io.Writer }

func (p *printer) help(name, text string) { _, _ = fmt.Fprintf(p.w, "# HELP %s %s\n", name, text) }
func (p *printer) typ(name, kind string)  { _, _ = fmt.Fprintf(p.w, "# TYPE %s %s\n", name, kind) }
func (p *printer) line(format string, args ...any) {
	_, _ = fmt.Fprintf(p.w, format, args...)
}

// formatFloat renders a float in the shortest representation that round-trips,
// which is what Prometheus parsers accept.
func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// formatSeconds renders a duration as seconds, using the same shortest
// round-tripping representation (so 1ms is "0.001" and 1ns is "1e-09").
func formatSeconds(d time.Duration) string {
	return strconv.FormatFloat(float64(d)/float64(time.Second), 'g', -1, 64)
}

// label renders a quoted, escaped Prometheus label value.
func label(v string) string {
	return `"` + escapeLabel(v) + `"`
}

// escapeLabel applies the Prometheus label-value escaping rules: backslash,
// double quote and newline, handled in a single pass.
func escapeLabel(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
