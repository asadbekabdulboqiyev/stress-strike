package prom

import (
	"bytes"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
)

// --- tiny exposition parser (test-only) -------------------------------------

type parsedExposition struct {
	samples map[string]float64
	help    map[string]string
	typ     map[string]string
	order   []string
}

// parseExposition parses Prometheus text exposition into a lookup table. It
// understands HELP/TYPE directives, `metric{labels} value` and bare
// `metric value` lines, including escaped label values.
func parseExposition(t *testing.T, text string) parsedExposition {
	t.Helper()
	p := parsedExposition{
		samples: make(map[string]float64),
		help:    make(map[string]string),
		typ:     make(map[string]string),
	}
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			fields := strings.SplitN(line, " ", 3)
			if len(fields) != 3 {
				t.Fatalf("line %d: malformed comment %q", i+1, line)
			}
			switch fields[1] {
			case "HELP":
				name, help, _ := strings.Cut(fields[2], " ")
				if name == "" || help == "" {
					t.Fatalf("line %d: malformed HELP %q", i+1, line)
				}
				p.help[name] = help
			case "TYPE":
				name, kind, _ := strings.Cut(fields[2], " ")
				if name == "" || kind == "" {
					t.Fatalf("line %d: malformed TYPE %q", i+1, line)
				}
				p.typ[name] = kind
			default:
				t.Fatalf("line %d: unknown directive %q", i+1, line)
			}
			continue
		}
		name, labels, value := parseSample(t, line)
		key := sampleKey(name, labels)
		if _, dup := p.samples[key]; dup {
			t.Fatalf("line %d: duplicate sample %s", i+1, key)
		}
		p.samples[key] = value
		p.order = append(p.order, key)
	}
	return p
}

// parseSample returns the metric name, the label set exactly as written between
// the braces (empty for an unlabelled sample) and the value.
func parseSample(t *testing.T, line string) (string, string, float64) {
	t.Helper()
	if open := strings.IndexByte(line, '{'); open >= 0 {
		name := line[:open]
		closeIdx := findClosingBrace(t, line, open)
		labels := line[open+1 : closeIdx]
		parseLabels(t, labels) // validate
		rest := strings.TrimSpace(line[closeIdx+1:])
		return name, labels, parseValue(t, rest)
	}
	sep := strings.LastIndexByte(line, ' ')
	if sep < 0 {
		t.Fatalf("malformed sample line %q", line)
	}
	return strings.TrimSpace(line[:sep]), "", parseValue(t, strings.TrimSpace(line[sep+1:]))
}

// sampleKey builds a lookup key preserving the emitted label order.
func sampleKey(name, labels string) string {
	if labels == "" {
		return name
	}
	return name + "{" + labels + "}"
}

// findClosingBrace returns the index of the `}` that closes the label set,
// skipping `}` characters inside escaped, quoted label values.
func findClosingBrace(t *testing.T, line string, open int) int {
	t.Helper()
	inQuote := false
	for i := open + 1; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\\':
			i++ // skip the escaped byte
		case c == '"':
			inQuote = !inQuote
		case c == '}' && !inQuote:
			return i
		}
	}
	t.Fatalf("unterminated label set in %q", line)
	return -1
}

func parseLabels(t *testing.T, s string) map[string]string {
	t.Helper()
	out := make(map[string]string)
	i := 0
	for i < len(s) {
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			t.Fatalf("malformed label set %q", s)
		}
		eq += i
		key := strings.TrimSpace(s[i:eq])
		if eq+1 >= len(s) || s[eq+1] != '"' {
			t.Fatalf("label %q must have a quoted value in %q", key, s)
		}
		var val strings.Builder
		j := eq + 2
		for j < len(s) {
			c := s[j]
			if c == '\\' {
				if j+1 >= len(s) {
					t.Fatalf("dangling escape in label set %q", s)
				}
				switch s[j+1] {
				case 'n':
					val.WriteByte('\n')
				case '"':
					val.WriteByte('"')
				case '\\':
					val.WriteByte('\\')
				default:
					val.WriteByte(s[j+1])
				}
				j += 2
				continue
			}
			if c == '"' {
				break
			}
			val.WriteByte(c)
			j++
		}
		if j >= len(s) {
			t.Fatalf("unterminated label value in %q", s)
		}
		out[key] = val.String()
		j++ // closing quote
		if j < len(s) && s[j] == ',' {
			j++
		}
		i = j
	}
	return out
}

func parseValue(t *testing.T, s string) float64 {
	t.Helper()
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		t.Fatalf("invalid sample value %q: %v", s, err)
	}
	return v
}

// --- helpers ----------------------------------------------------------------

// newFixtureTelemetry builds a telemetry with two steps and known latencies:
//
//	checkout: 1ms/200, 2ms/200, 3ms/500(timeout)
//	login:    5ms/200, 10ms/401(auth)
//
// Every observation is also recorded against Overall (as the engine does), so
// the run-wide totals and the histogram match the per-step sums.
func newFixtureTelemetry() *metrics.Telemetry {
	tel := metrics.NewTelemetry()
	tel.Start = time.Now().Add(-10 * time.Second)

	checkout := metrics.NewStepStats("checkout")
	login := metrics.NewStepStats("login")
	tel.AddStep(checkout)
	tel.AddStep(login)

	record := func(s *metrics.StepStats, d time.Duration, code int, errName string) {
		s.Record(d, code, errName)
		tel.Overall.Record(d, code, errName)
	}
	record(checkout, 1*time.Millisecond, 200, "")
	record(checkout, 2*time.Millisecond, 200, "")
	record(checkout, 3*time.Millisecond, 500, "timeout")
	record(login, 5*time.Millisecond, 200, "")
	record(login, 10*time.Millisecond, 401, "auth")

	tel.ActiveUsers.Store(7)
	tel.PeakUsers.Store(9)
	tel.Finish()
	return tel
}

func mustWrite(t *testing.T, tel *metrics.Telemetry) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, tel); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.String()
}

// familyKeys returns the keys in p.order that begin with prefix.
func familyKeys(p parsedExposition, prefix string) []string {
	var out []string
	for _, k := range p.order {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

// labelsFromKey decodes the label set embedded in a canonical sample key.
func labelsFromKey(t *testing.T, key string) map[string]string {
	t.Helper()
	open := strings.IndexByte(key, '{')
	if open < 0 {
		return nil
	}
	return parseLabels(t, strings.TrimSuffix(key[open+1:], "}"))
}

// --- tests ------------------------------------------------------------------

func TestRenderExposition(t *testing.T) {
	out := mustWrite(t, newFixtureTelemetry())
	p := parseExposition(t, out)

	wantFamilies := map[string]string{
		"ss_requests_total":           "counter",
		"ss_errors_total":             "counter",
		"ss_status_codes_total":       "counter",
		"ss_errors_by_name_total":     "counter",
		"ss_request_duration_seconds": "histogram",
		"ss_step_requests_total":      "counter",
		"ss_step_errors_total":        "counter",
		"ss_rps":                      "gauge",
		"ss_active_users":             "gauge",
		"ss_peak_users":               "gauge",
		"ss_error_rate":               "gauge",
		"ss_uptime_seconds":           "gauge",
	}
	for name, kind := range wantFamilies {
		if p.help[name] == "" {
			t.Errorf("missing # HELP for %s", name)
		}
		if got := p.typ[name]; got != kind {
			t.Errorf("# TYPE %s = %q, want %q", name, got, kind)
		}
	}

	// Run-wide, unlabelled counters.
	wantSamples := map[string]float64{
		"ss_requests_total":                             5,
		"ss_errors_total":                               2,
		`ss_status_codes_total{code="200"}`:             3,
		`ss_status_codes_total{code="401"}`:             1,
		`ss_status_codes_total{code="500"}`:             1,
		`ss_errors_by_name_total{error="auth"}`:         1,
		`ss_errors_by_name_total{error="timeout"}`:      1,
		"ss_request_duration_seconds_count":             5,
		`ss_request_duration_seconds_bucket{le="+Inf"}`: 5,
		`ss_step_requests_total{step="checkout"}`:       3,
		`ss_step_requests_total{step="login"}`:          2,
		`ss_step_errors_total{step="checkout"}`:         1,
		`ss_step_errors_total{step="login"}`:            1,
		"ss_active_users":                               7,
		"ss_peak_users":                                 9,
	}
	for key, want := range wantSamples {
		got, ok := p.samples[key]
		if !ok {
			t.Errorf("missing sample %s", key)
			continue
		}
		if got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}

	// Histogram sum: 1+2+3+5+10 = 21ms = 0.021s.
	if got, ok := p.samples["ss_request_duration_seconds_sum"]; !ok {
		t.Error("missing histogram sum")
	} else if math.Abs(got-0.021) > 1e-9 {
		t.Errorf("histogram sum = %v, want 0.021", got)
	}

	// error rate = 2 errors / 5 requests.
	if got := p.samples["ss_error_rate"]; math.Abs(got-0.4) > 1e-9 {
		t.Errorf("ss_error_rate = %v, want 0.4", got)
	}
	// rps ~= 5 requests / 10s.
	if got := p.samples["ss_rps"]; math.Abs(got-0.5) > 0.05 {
		t.Errorf("ss_rps = %v, want ~0.5", got)
	}
	if got := p.samples["ss_uptime_seconds"]; got < 10 || got > 11 {
		t.Errorf("ss_uptime_seconds = %v, want ~10", got)
	}

	// Ordering must be deterministic: status codes ascending, error names and
	// step names lexicographic.
	assertOrder(t, familyKeys(p, "ss_status_codes_total{"), []string{
		`ss_status_codes_total{code="200"}`,
		`ss_status_codes_total{code="401"}`,
		`ss_status_codes_total{code="500"}`,
	})
	assertOrder(t, familyKeys(p, "ss_errors_by_name_total{"), []string{
		`ss_errors_by_name_total{error="auth"}`,
		`ss_errors_by_name_total{error="timeout"}`,
	})
	assertOrder(t, familyKeys(p, "ss_step_requests_total{"), []string{
		`ss_step_requests_total{step="checkout"}`,
		`ss_step_requests_total{step="login"}`,
	})

	assertBucketsMonotonic(t, p, 5)
}

// TestRenderEmitsEveryCumulativeBucket checks that the histogram exposes every
// bucket returned by CumulativeBuckets (plus +Inf), not a subset.
func TestRenderEmitsEveryCumulativeBucket(t *testing.T) {
	tel := newFixtureTelemetry()
	out := mustWrite(t, tel)
	p := parseExposition(t, out)

	snap := tel.Overall.Latency.Snapshot()
	wantFinite := len(snap.CumulativeBuckets())

	var finite, inf int
	var lastCount float64
	for _, key := range familyKeys(p, "ss_request_duration_seconds_bucket{") {
		labels := labelsFromKey(t, key)
		if labels["le"] == "+Inf" {
			inf++
			continue
		}
		finite++
		v := p.samples[key]
		if v < lastCount {
			t.Fatalf("bucket %s = %v decreased below %v", key, v, lastCount)
		}
		lastCount = v
	}
	if finite != wantFinite {
		t.Errorf("finite buckets = %d, want %d", finite, wantFinite)
	}
	t.Logf("exposition: %d finite le buckets, %d bytes total", finite, len(out))
	if inf != 1 {
		t.Errorf("+Inf buckets = %d, want exactly 1", inf)
	}
	// The last finite bucket is >= the +Inf count only if cumulative; it must
	// never exceed it.
	if lastCount > p.samples[`ss_request_duration_seconds_bucket{le="+Inf"}`] {
		t.Errorf("last finite bucket %v exceeds +Inf %v", lastCount, p.samples[`ss_request_duration_seconds_bucket{le="+Inf"}`])
	}
}

func assertOrder(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

// assertBucketsMonotonic verifies the cumulative `le` buckets are
// non-decreasing and that `le="+Inf"` equals the histogram count.
func assertBucketsMonotonic(t *testing.T, p parsedExposition, wantCount float64) {
	t.Helper()
	var (
		prev  float64
		seen  int
		lastI float64
	)
	for _, key := range familyKeys(p, "ss_request_duration_seconds_bucket{") {
		le := labelsFromKey(t, key)["le"]
		v := p.samples[key]
		if le == "+Inf" {
			if v != wantCount {
				t.Errorf("+Inf bucket = %v, want count %v", v, wantCount)
			}
			if seen == 0 {
				t.Error("no finite buckets emitted")
			}
			if lastI > v {
				t.Errorf("last finite bucket %v exceeds +Inf %v", lastI, v)
			}
			return
		}
		if v < prev {
			t.Errorf("bucket le=%s count %v decreased below previous %v", le, v, prev)
		}
		prev = v
		lastI = v
		seen++
	}
	t.Error("no +Inf bucket found")
}

func TestRenderDeterministic(t *testing.T) {
	tel := newFixtureTelemetry()
	if first, second := mustWrite(t, tel), mustWrite(t, tel); first != second {
		t.Fatal("two Write calls for the same snapshot produced different output")
	}
}

func TestRenderEscapesLabels(t *testing.T) {
	stepName := "we\"ird\nstep"
	errName := "bad\"err\nx"

	step := metrics.NewStepStats(stepName)
	step.Record(1*time.Millisecond, 200, errName)

	tel := metrics.NewTelemetry()
	tel.AddStep(step)
	tel.Overall.Record(1*time.Millisecond, 200, errName)

	out := mustWrite(t, tel)

	// A literal newline inside a label value would break the line-oriented
	// format, so it must never appear raw.
	if strings.Contains(out, "we\"ird\nstep") {
		t.Fatalf("unescaped newline/quote leaked into output:\n%s", out)
	}
	if !strings.Contains(out, `ss_step_requests_total{step="we\"ird\nstep"} 1`) {
		t.Fatalf("expected escaped step label, output:\n%s", out)
	}
	if !strings.Contains(out, `ss_errors_by_name_total{error="bad\"err\nx"} 1`) {
		t.Fatalf("expected escaped error label, output:\n%s", out)
	}

	p := parseExposition(t, out)
	key := `ss_step_requests_total{step="we\"ird\nstep"}`
	if _, ok := p.samples[key]; !ok {
		t.Fatalf("escaped step label did not appear as a sample key; have %v", p.order)
	}
	if got := labelsFromKey(t, key)["step"]; got != stepName {
		t.Fatalf("decoded step label = %q, want %q", got, stepName)
	}
}

func TestRenderNilAndZeroTelemetry(t *testing.T) {
	cases := map[string]*metrics.Telemetry{
		"nil":     nil,
		"zero":    {},
		"overall": {Overall: metrics.NewStepStats("overall")},
	}
	for label, tel := range cases {
		for _, out := range []string{mustWrite(t, tel), mustRenderExporter(t, tel)} {
			p := parseExposition(t, out)
			if got := p.samples["ss_requests_total"]; got != 0 {
				t.Errorf("%s: ss_requests_total = %v, want 0", label, got)
			}
			if got := p.samples["ss_errors_total"]; got != 0 {
				t.Errorf("%s: ss_errors_total = %v, want 0", label, got)
			}
			if got := p.samples["ss_request_duration_seconds_count"]; got != 0 {
				t.Errorf("%s: histogram count = %v, want 0", label, got)
			}
			if got := p.samples[`ss_request_duration_seconds_bucket{le="+Inf"}`]; got != 0 {
				t.Errorf("%s: +Inf bucket = %v, want 0", label, got)
			}
			if got := p.samples["ss_error_rate"]; got != 0 {
				t.Errorf("%s: ss_error_rate = %v, want 0", label, got)
			}
			if got := p.samples["ss_uptime_seconds"]; got != 0 {
				t.Errorf("%s: ss_uptime_seconds = %v, want 0", label, got)
			}
			if _, ok := p.samples["ss_rps"]; !ok {
				t.Errorf("%s: ss_rps gauge missing", label)
			}
		}
	}
}

func mustRenderExporter(t *testing.T, tel *metrics.Telemetry) string {
	t.Helper()
	var buf bytes.Buffer
	if err := New(tel).Render(&buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return buf.String()
}

func TestRenderMergesDuplicateStepNames(t *testing.T) {
	// Two steps sharing a name must not produce duplicate series.
	tel := metrics.NewTelemetry()
	for i := 0; i < 2; i++ {
		s := metrics.NewStepStats("dup")
		s.Record(time.Millisecond, 200, "")
		tel.AddStep(s)
		tel.Overall.Record(time.Millisecond, 200, "")
	}
	p := parseExposition(t, mustWrite(t, tel))
	if got := p.samples[`ss_step_requests_total{step="dup"}`]; got != 2 {
		t.Errorf("merged step requests = %v, want 2", got)
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	for name, h := range map[string]http.Handler{
		"exporter": New(newFixtureTelemetry()).Handler(),
		"metrics":  NewMetrics().Handler(),
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/metrics", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", name, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
			t.Errorf("%s: Allow header = %q, want GET", name, allow)
		}
	}
}

func TestHandlerContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	New(newFixtureTelemetry()).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != ContentType {
		t.Errorf("Content-Type = %q, want %q", ct, ContentType)
	}
	if body := rec.Body.String(); !strings.Contains(body, "ss_requests_total 5") {
		t.Errorf("body missing ss_requests_total 5:\n%.200s", body)
	}
}

// TestMetricsSelfMode exercises the backward-compatible Metrics API: its own
// counters are exported under the synthetic "self" step.
func TestMetricsSelfMode(t *testing.T) {
	m := NewMetrics()
	m.IncRequests()
	m.IncRequests()
	m.IncRequests()
	m.IncErrors()
	m.ObserveLatency(2 * time.Millisecond)
	m.ObserveLatency(-time.Second) // clamped to 0 by the histogram

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != ContentType {
		t.Errorf("Content-Type = %q, want %q", ct, ContentType)
	}

	p := parseExposition(t, rec.Body.String())
	if got := p.samples["ss_requests_total"]; got != 3 {
		t.Errorf("requests = %v, want 3", got)
	}
	if got := p.samples["ss_errors_total"]; got != 1 {
		t.Errorf("errors = %v, want 1", got)
	}
	if got := p.samples[`ss_errors_by_name_total{error="unknown"}`]; got != 1 {
		t.Errorf("errors-by-name = %v, want 1", got)
	}
	if got := p.samples[`ss_step_requests_total{step="self"}`]; got != 3 {
		t.Errorf("self step requests = %v, want 3", got)
	}
	if got := p.samples[`ss_step_errors_total{step="self"}`]; got != 1 {
		t.Errorf("self step errors = %v, want 1", got)
	}
	if got := p.samples["ss_request_duration_seconds_count"]; got != 2 {
		t.Errorf("histogram count = %v, want 2", got)
	}
	if got := p.samples["ss_request_duration_seconds_sum"]; math.Abs(got-0.002) > 1e-9 {
		t.Errorf("histogram sum = %v, want 0.002", got)
	}
	if got := p.samples["ss_error_rate"]; math.Abs(got-1.0/3.0) > 1e-9 {
		t.Errorf("error rate = %v, want 1/3", got)
	}
}

// TestExporterFromTelemetryThroughMetrics covers the FromTelemetry bridge.
func TestExporterFromTelemetryThroughMetrics(t *testing.T) {
	m := FromTelemetry(newFixtureTelemetry())
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	p := parseExposition(t, rec.Body.String())
	if got := p.samples["ss_requests_total"]; got != 5 {
		t.Errorf("requests = %v, want 5", got)
	}
	if got := p.samples[`ss_step_requests_total{step="checkout"}`]; got != 3 {
		t.Errorf("checkout requests = %v, want 3", got)
	}
}

func TestExporterWriteTo(t *testing.T) {
	exp := New(newFixtureTelemetry())
	var buf bytes.Buffer
	n, err := exp.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if int(n) != buf.Len() {
		t.Errorf("WriteTo reported %d bytes, buffer holds %d", n, buf.Len())
	}
	if !strings.Contains(buf.String(), "ss_requests_total 5") {
		t.Errorf("WriteTo output missing ss_requests_total 5")
	}

	// Render must produce the same document as WriteTo.
	var rendered bytes.Buffer
	if err := exp.Render(&rendered); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if rendered.String() != buf.String() {
		t.Error("Render and WriteTo produced different documents")
	}
}

func TestHandlerRejectsNilTelemetry(t *testing.T) {
	rec := httptest.NewRecorder()
	New(nil).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ss_requests_total 0") {
		t.Errorf("nil telemetry body missing zero request counter")
	}
}

// TestConcurrentScrapes exercises Handler, WriteTo and Write from many
// goroutines at once. Run with -race: it must not report a data race, and every
// response must be a complete, well-formed document.
func TestConcurrentScrapes(t *testing.T) {
	tel := newFixtureTelemetry()
	metricsHandler := NewMetrics().Handler()
	exporterHandler := New(tel).Handler()
	exp := New(tel)

	const (
		workers    = 8
		iterations = 8
	)
	var wg sync.WaitGroup
	errs := make(chan string, workers*iterations*3)

	check := func(body string) {
		if !strings.Contains(body, "ss_requests_total 5") {
			errs <- "document missing overall request count"
			return
		}
		if !strings.HasSuffix(body, "\n") {
			errs <- "document does not end with a newline"
		}
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				rec := httptest.NewRecorder()
				exporterHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
				check(rec.Body.String())
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				rec := httptest.NewRecorder()
				metricsHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
				if rec.Code != http.StatusOK {
					errs <- "self handler returned non-200"
					return
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				var buf bytes.Buffer
				if _, err := exp.WriteTo(&buf); err != nil {
					errs <- "WriteTo failed"
					return
				}
				check(buf.String())
			}
		}()
	}

	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

func TestEscapeLabel(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		"quote\"here": `quote\"here`,
		"back\\slash": `back\\slash`,
		"new\nline":   `new\nline`,
		"mix\\\"\n":   `mix\\\"\n`,
	}
	for in, want := range cases {
		if got := escapeLabel(in); got != want {
			t.Errorf("escapeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatSeconds(t *testing.T) {
	cases := map[time.Duration]string{
		0:                "0",
		time.Nanosecond:  "1e-09",
		time.Microsecond: "1e-06",
		time.Millisecond: "0.001",
		time.Second:      "1",
		time.Minute:      "60",
	}
	for d, want := range cases {
		if got := formatSeconds(d); got != want {
			t.Errorf("formatSeconds(%v) = %q, want %q", d, got, want)
		}
	}
}
