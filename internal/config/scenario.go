package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/fingerprint"
)

const (
	ProfileSteady      = "steady"
	ProfileSoak        = "soak"
	ProfileLinearRamp  = "linear-ramp"
	ProfileSpike       = "spike"
	ProfileWave        = "wave"
	ProfileConstantRPS = "constant-rps"
	ProfileBurst       = "burst"
	maxUsers           = 100_000
	maxRPS             = 1_000_000
	maxDuration        = 7 * 24 * 60 * 60 // 7 days, in seconds
	maxTimeout         = 5 * 60           // 5 minutes, in seconds
)

type Profile struct {
	Type            string `yaml:"type" json:"type"`
	Users           int    `yaml:"users" json:"users"`
	Duration        int    `yaml:"duration" json:"duration"`
	Warmup          int    `yaml:"warmup" json:"warmup"`
	RampUp          int    `yaml:"ramp_up" json:"ramp_up"`
	SpikeUsers      int    `yaml:"spike_users" json:"spike_users"`
	SpikeWarmup     int    `yaml:"spike_warmup" json:"spike_warmup"`
	SpikeHold       int    `yaml:"spike_hold" json:"spike_hold"`
	WavePeriod      int    `yaml:"wave_period" json:"wave_period"`
	RPS             int    `yaml:"rps" json:"rps"`
	TargetRPS       int    `yaml:"target_rps" json:"target_rps"`
	Timeout         int    `yaml:"timeout" json:"timeout"`
	KeepAlive       *bool  `yaml:"keep_alive" json:"keep_alive"`
	Gate            bool   `yaml:"gate" json:"gate"`
	Http2           *bool  `yaml:"http2" json:"http2"`
	WAFEnabled      bool   `yaml:"waf_enabled" json:"waf_enabled"`
	TLSFingerprint  string `yaml:"tls_fingerprint" json:"tls_fingerprint"`
	RateLimitConfig `yaml:"rate_limit" json:"rate_limit"`
}

// HTTP2Enabled reports whether HTTP/2 should be negotiated. The zero value
// (nil, not present in YAML) means "enabled" — Go's transport already attempts
// HTTP/2 by default. An explicit `http2: false` opts into HTTP/1.1 only.
func (p *Profile) HTTP2Enabled() bool {
	return p.Http2 == nil || *p.Http2
}

type Extract struct {
	Name string `yaml:"name" json:"name"`
	From string `yaml:"from" json:"from"`
	Path string `yaml:"path" json:"path"`
}

type RateLimitConfig struct {
	DefaultRPS   int           `yaml:"default_rps" json:"default_rps"`
	MaxBurst     int           `yaml:"max_burst" json:"max_burst"`
	IPRPS        int           `yaml:"ip_rps" json:"ip_rps"`
	IPBurst      int           `yaml:"ip_burst" json:"ip_burst"`
	SeenCacheTTL time.Duration `yaml:"seen_cache_ttl" json:"seen_cache_ttl"`
}

// Assertion validates a single property of a step response. Type is one of
// "status", "json_path" or "regex"; Value holds the expected value.
type Assertion struct {
	Type  string `yaml:"type" json:"type"`   // status | json_path | regex
	Value string `yaml:"value" json:"value"` // "200", "2xx", "data.token", regex pattern
}

type Step struct {
	Name       string            `yaml:"name" json:"name"`
	Type       string            `yaml:"type" json:"type"` // http (default) | ws | grpc | grpc-stream | tcp | udp | if
	Method     string            `yaml:"method" json:"method"`
	URL        string            `yaml:"url" json:"url"`
	Headers    map[string]string `yaml:"headers" json:"headers"`
	Body       string            `yaml:"body" json:"body"`
	Extract    []Extract         `yaml:"extract" json:"extract"`
	Assertions []Assertion       `yaml:"assertions" json:"assertions"`
	Timeout    int               `yaml:"timeout" json:"timeout"`

	// Protocol-specific options (all optional; empty keeps protocol defaults).
	FrameType     string `yaml:"frame_type" json:"frame_type"`         // ws: text (default) | binary
	GrpcMethod    string `yaml:"grpc_method" json:"grpc_method"`       // grpc: "/pkg.Service/Method"; empty = health check
	GrpcStream    bool   `yaml:"grpc_stream" json:"grpc_stream"`       // grpc: client-streaming RPC (body lines → SendMsg, then RecvMsg)
	AwaitResponse bool   `yaml:"await_response" json:"await_response"` // udp: wait for a reply and measure RTT
	Session       bool   `yaml:"session" json:"session"`               // ws|tcp: keep one persistent connection per virtual user

	// Control-flow (all optional; zero values keep the documented defaults).
	ThinkTime    float64 `yaml:"think_time" json:"think_time"`         // seconds to pause after this step (0.1 = 100ms)
	SkipOnError  bool    `yaml:"skip_on_error" json:"skip_on_error"`   // skip this step when the previous step errored (iteration continues)
	OnError      string  `yaml:"on_error" json:"on_error"`             // "continue" → next step; "stop" → abort iteration (default "stop")
	Retries      int     `yaml:"retries" json:"retries"`               // extra attempts on failure (default 0)
	RetryBackoff float64 `yaml:"retry_backoff" json:"retry_backoff"`   // seconds between retries (default 0.1)
	StopOnStatus string  `yaml:"stop_on_status" json:"stop_on_status"` // "4xx"|"5xx"|"2xx"|exact code: halt the entire run

	// Conditional branching (type: if).
	Condition string `yaml:"condition" json:"condition"` // "$var == v" | "$var != v" | "$var contains \"s\"" | "$var =~ re"
	Steps     []Step `yaml:"steps" json:"steps"`         // nested steps run when condition is true

	// Parsed at Normalize() time; never serialized (engine reads these).
	Cond            *Condition `yaml:"-" json:"-"`
	StopStatusLower int        `yaml:"-" json:"-"`
	StopStatusUpper int        `yaml:"-" json:"-"`
}

// Condition is a single comparison compiled from a step condition expression.
// Supported operators:
//
//	"=="        exact equality (numeric comparison when both sides parse as numbers)
//	"!="        inequality
//	"contains"  substring match
//	"=~"        regular-expression match
type Condition struct {
	Var      string `json:"var"`
	Op       string `json:"op"`
	Expected string `json:"expected"`
	re       *regexp.Regexp
}

var conditionRe = regexp.MustCompile(`^(\$\{\s*[A-Za-z0-9_.-]+\s*\}|\{\{\s*[A-Za-z0-9_.-]+\s*\}\}|[A-Za-z0-9_.-]+)\s*(==|!=|=~|contains)\s*(.+)$`)

// ParseCondition compiles a condition expression such as "${login_status} == 200".
// The variable may be written as ${var}, {{var}} or bare; the expected value may
// be quoted with " or '. Only a single comparison is supported (no AND/OR) so the
// semantics stay simple and predictable.
func ParseCondition(expr string) (*Condition, error) {
	s := strings.TrimSpace(expr)
	if s == "" {
		return nil, fmt.Errorf("empty condition")
	}
	m := conditionRe.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("invalid condition %q: expected form \"$var == value\" (operators: ==, !=, contains, =~)", expr)
	}
	rawVal := strings.TrimSpace(m[3])
	// Reject obviously doubled operators such as "a === b" or "a !== b",
	// where the "value" looks like another operator token.
	if rawVal != "" && (rawVal[0] == '=' || rawVal[0] == '!' || rawVal[0] == '~') {
		return nil, fmt.Errorf("invalid condition %q: unexpected operator-like value %q", expr, rawVal)
	}
	c := &Condition{
		Var:      strings.Trim(m[1], "${} "),
		Op:       m[2],
		Expected: strings.Trim(rawVal, `"'`),
	}
	if c.Op == "=~" {
		re, err := regexp.Compile(c.Expected)
		if err != nil {
			return nil, fmt.Errorf("invalid condition regex %q: %w", c.Expected, err)
		}
		c.re = re
	}
	return c, nil
}

// Eval reports whether the condition holds against the given variables.
// A variable that is missing from the map evaluates to false for every operator.
func (c *Condition) Eval(vars map[string]string) bool {
	if c == nil {
		return false
	}
	actual, ok := vars[c.Var]
	if !ok {
		return false
	}
	switch c.Op {
	case "==":
		return compareValues(actual, c.Expected) == 0
	case "!=":
		return compareValues(actual, c.Expected) != 0
	case "contains":
		return strings.Contains(actual, c.Expected)
	case "=~":
		return c.re != nil && c.re.MatchString(actual)
	default:
		return false
	}
}

// compareValues compares two strings, numerically when both sides parse as
// floats (so "${status} == 200" holds for "200" and "200.0" alike).
func compareValues(a, b string) int {
	af, aerr := strconv.ParseFloat(strings.TrimSpace(a), 64)
	bf, berr := strconv.ParseFloat(strings.TrimSpace(b), 64)
	if aerr == nil && berr == nil {
		switch {
		case af < bf:
			return -1
		case af > bf:
			return 1
		default:
			return 0
		}
	}
	return strings.Compare(a, b)
}

// parseStatusMatcher compiles a stop_on_status spec ("4xx", "5xx", "2xx" or an
// exact code like "429") into an inclusive [lower, upper] status range. An empty
// spec disables the matcher (lower == upper == 0).
func parseStatusMatcher(spec string) (lower, upper int, err error) {
	switch strings.TrimSpace(spec) {
	case "":
		return 0, 0, nil
	case "2xx":
		return 200, 299, nil
	case "3xx":
		return 300, 399, nil
	case "4xx":
		return 400, 499, nil
	case "5xx":
		return 500, 599, nil
	}
	if code, perr := strconv.Atoi(strings.TrimSpace(spec)); perr == nil {
		if code < 100 || code > 599 {
			return 0, 0, fmt.Errorf("stop_on_status %q is out of range (100-599)", spec)
		}
		return code, code, nil
	}
	// "Nxx" pattern not covered by the classes above.
	if len(spec) == 3 && spec[1] == 'x' && spec[2] == 'x' && spec[0] >= '0' && spec[0] <= '9' {
		return 0, 0, fmt.Errorf("unsupported status class %q (use 2xx, 3xx, 4xx or 5xx)", spec)
	}
	return 0, 0, fmt.Errorf("invalid stop_on_status %q (use \"4xx\", \"5xx\", \"2xx\" or an exact code like \"429\")", spec)
}

// SLA defines pass/fail thresholds evaluated against aggregate results after
// a completed run. Any zero field disables that specific check. When an SLA
// is present and any check fails, the CLI exits with code 2 so CI/CD jobs can
// fail the pipeline on performance regressions.
type SLA struct {
	MaxP99Ms        float64 `yaml:"max_p99_ms" json:"max_p99_ms"`
	MaxAvgMs        float64 `yaml:"max_avg_ms" json:"max_avg_ms"`
	MaxErrorRatePct float64 `yaml:"max_error_rate_pct" json:"max_error_rate_pct"`
	MinRPS          float64 `yaml:"min_rps" json:"min_rps"`
}

func (s *SLA) Normalize() error {
	if s == nil {
		return nil
	}
	for name, v := range map[string]float64{
		"max_p99_ms":         s.MaxP99Ms,
		"max_avg_ms":         s.MaxAvgMs,
		"max_error_rate_pct": s.MaxErrorRatePct,
		"min_rps":            s.MinRPS,
	} {
		if v < 0 {
			return fmt.Errorf("sla.%s must be non-negative, got %v", name, v)
		}
	}
	return nil
}

// Empty reports whether no threshold is configured at all.
func (s *SLA) Empty() bool {
	return s == nil || (s.MaxP99Ms <= 0 && s.MaxAvgMs <= 0 && s.MaxErrorRatePct <= 0 && s.MinRPS <= 0)
}

type Scenario struct {
	Name               string            `yaml:"name" json:"name"`
	BaseURL            string            `yaml:"base_url" json:"base_url"`
	Profile            Profile           `yaml:"load_profile" json:"load_profile"`
	Steps              []Step            `yaml:"steps" json:"steps"`
	Variables          map[string]string `yaml:"variables" json:"variables"`
	SLA                *SLA              `yaml:"sla" json:"sla,omitempty"`
	PreWarm            bool              `yaml:"pre_warm" json:"pre_warm"`
	PreWarmConnections int               `yaml:"pre_warm_connections" json:"pre_warm_connections"`
	PreWarmTime        time.Duration     `yaml:"-" json:"-"`
}

func (p *Profile) Normalize() error {
	if p.Type == "" {
		p.Type = ProfileSteady
	}
	// "burst" is sugar for steady + zero ramp-up: every virtual user starts
	// at t=0 and loops at maximum speed (no RPS cap) for a short window,
	// defaulting to 3 seconds. The transform happens before validation so the
	// rest of the pipeline only ever sees the steady shape.
	switch p.Type {
	case ProfileBurst:
		if p.Duration <= 0 {
			p.Duration = 3
		}
		p.Type = ProfileSteady
		p.RampUp = 0
	}
	switch p.Type {
	case ProfileSteady, ProfileSoak, ProfileLinearRamp, ProfileSpike, ProfileWave, ProfileConstantRPS:
	default:
		return fmt.Errorf("unsupported load profile %q (use: %s, %s, %s, %s, %s, %s, %s)", p.Type, ProfileSteady, ProfileSoak, ProfileLinearRamp, ProfileSpike, ProfileWave, ProfileConstantRPS, ProfileBurst)
	}

	if p.Type == ProfileConstantRPS {
		if p.TargetRPS <= 0 {
			return fmt.Errorf("constant-rps profile requires target_rps > 0")
		}
		if p.TargetRPS > maxRPS {
			return fmt.Errorf("target_rps (%d) exceeds maximum of %d", p.TargetRPS, maxRPS)
		}
	} else {
		if p.Users < 1 {
			p.Users = 10
		}
		if p.Users > maxUsers {
			return fmt.Errorf("users (%d) exceeds maximum of %d", p.Users, maxUsers)
		}
	}
	if p.Duration <= 0 {
		p.Duration = 30
	}
	if p.Duration > maxDuration {
		return fmt.Errorf("duration (%d) exceeds maximum of %d seconds (%d days)", p.Duration, maxDuration, maxDuration/(24*60*60))
	}
	if p.Warmup < 0 {
		p.Warmup = 0
	}
	if p.Warmup >= p.Duration {
		return fmt.Errorf("warmup (%ds) must be smaller than duration (%ds)", p.Warmup, p.Duration)
	}
	if p.Gate && p.Users < 2 {
		return fmt.Errorf("gate mode (race attack) requires at least 2 users firing simultaneously")
	}
	if p.RampUp <= 0 {
		p.RampUp = p.Duration / 2
		if p.RampUp < 1 {
			p.RampUp = 1
		}
	}
	if p.Timeout <= 0 {
		p.Timeout = 5
	}
	if p.Timeout > maxTimeout {
		return fmt.Errorf("timeout (%d) exceeds maximum of %d seconds (%d minutes)", p.Timeout, maxTimeout, maxTimeout/60)
	}
	if p.Type == ProfileWave {
		if p.WavePeriod <= 0 {
			p.WavePeriod = p.Duration / 3
		}
		if p.WavePeriod < 1 {
			p.WavePeriod = 1
		}
	}
	if p.Type == ProfileSpike {
		if p.SpikeUsers <= 0 {
			p.SpikeUsers = p.Users * 10
		}
		if p.SpikeUsers > maxUsers {
			return fmt.Errorf("spike_users (%d) exceeds maximum of %d", p.SpikeUsers, maxUsers)
		}
		if p.SpikeWarmup < 0 {
			p.SpikeWarmup = 0
		}
		if p.SpikeWarmup > maxDuration {
			return fmt.Errorf("spike_warmup (%d) exceeds maximum of %d seconds", p.SpikeWarmup, maxDuration)
		}
		if p.SpikeHold <= 0 {
			p.SpikeHold = p.Duration
		}
		if p.SpikeHold > maxDuration {
			return fmt.Errorf("spike_hold (%d) exceeds maximum of %d seconds", p.SpikeHold, maxDuration)
		}
		if p.SpikeWarmup+p.SpikeHold > maxDuration {
			return fmt.Errorf("spike total duration (warmup+hold = %d) exceeds maximum of %d seconds", p.SpikeWarmup+p.SpikeHold, maxDuration)
		}
	}
	if !fingerprint.Profile(p.TLSFingerprint).Valid() {
		return fmt.Errorf("tls_fingerprint %q is not a known fingerprint (valid values: %s)",
			p.TLSFingerprint, strings.Join(fingerprint.Names(), ", "))
	}
	return nil
}

func (p *Profile) TotalDuration() int {
	switch p.Type {
	case ProfileSpike:
		return p.SpikeWarmup + p.SpikeHold
	default:
		return p.Duration
	}
}

// IsConstantRPS reports whether this profile uses direct RPS targeting.
func (p *Profile) IsConstantRPS() bool {
	return p.Type == ProfileConstantRPS
}

func (s *Scenario) Normalize() error {
	if s.Name == "" {
		s.Name = "unnamed"
	}
	if err := s.Profile.Normalize(); err != nil {
		return err
	}
	if err := s.SLA.Normalize(); err != nil {
		return err
	}
	if len(s.Steps) == 0 {
		return fmt.Errorf("scenario must define at least one step")
	}
	for i := range s.Steps {
		st := &s.Steps[i]
		if st.Name == "" {
			st.Name = fmt.Sprintf("step%d", i+1)
		}
		if err := normalizeStep(st, 0); err != nil {
			return err
		}
	}
	return nil
}

// maxStepNesting guards the recursion depth of type: if branches.
const maxStepNesting = 32

// normalizeStep validates a single step (or an if-branch) and fills in
// defaults, protocol aliases and parsed fields. It recurses for type: if.
func normalizeStep(st *Step, depth int) error {
	if depth > maxStepNesting {
		return fmt.Errorf("step %q: nesting exceeds maximum depth of %d", st.Name, maxStepNesting)
	}
	st.Type = strings.ToLower(strings.TrimSpace(st.Type))
	if st.Type == "" {
		st.Type = "http"
	}
	// "grpc-stream" is a convenience alias for type: grpc + grpc_stream: true.
	if st.Type == "grpc-stream" {
		st.Type = "grpc"
		st.GrpcStream = true
	}
	switch st.Type {
	case "http", "ws", "grpc", "tcp", "udp", "if":
	default:
		return fmt.Errorf("step %q: unsupported type %q (use http, ws, grpc, grpc-stream, tcp, udp, if)", st.Name, st.Type)
	}
	if st.GrpcStream && st.Type != "grpc" {
		return fmt.Errorf("step %q: grpc_stream is only valid on grpc steps", st.Name)
	}
	if st.Type == "if" {
		return normalizeIfStep(st, depth)
	}

	st.Method = strings.ToUpper(strings.TrimSpace(st.Method))
	if st.Method == "" {
		st.Method = "GET"
	}
	if st.URL == "" {
		return fmt.Errorf("step %q: url is required", st.Name)
	}
	if st.FrameType != "" {
		st.FrameType = strings.ToLower(strings.TrimSpace(st.FrameType))
		switch st.FrameType {
		case "text", "binary":
		default:
			return fmt.Errorf("step %q: unsupported frame_type %q (use text, binary)", st.Name, st.FrameType)
		}
	}
	if st.GrpcMethod != "" && !strings.HasPrefix(st.GrpcMethod, "/") {
		return fmt.Errorf("step %q: grpc_method must look like \"/package.Service/Method\"", st.Name)
	}
	if st.Type == "grpc" && st.GrpcStream && st.GrpcMethod == "" {
		return fmt.Errorf("step %q: grpc_stream requires grpc_method", st.Name)
	}
	if st.Type == "http" && !strings.Contains(st.URL, "://") && !strings.HasPrefix(st.URL, "/") {
		st.URL = "http://" + st.URL
	}
	if st.Timeout > maxTimeout {
		return fmt.Errorf("step %q: timeout (%d) exceeds maximum of %d seconds (%d minutes)", st.Name, st.Timeout, maxTimeout, maxTimeout/60)
	}
	if err := normalizeControlFlow(st); err != nil {
		return err
	}
	for j := range st.Extract {
		e := &st.Extract[j]
		if e.From == "" {
			e.From = "json"
		}
		switch e.From {
		case "json", "header", "body":
		default:
			return fmt.Errorf("step %q: unsupported extract.from %q (use json, header, body)", st.Name, e.From)
		}
	}
	for j := range st.Assertions {
		a := &st.Assertions[j]
		switch a.Type {
		case "status", "json_path", "regex":
		default:
			return fmt.Errorf("step %q: unsupported assertion type %q (use status, json_path, regex)", st.Name, a.Type)
		}
		if strings.TrimSpace(a.Value) == "" {
			return fmt.Errorf("step %q: assertion %q requires a non-empty value", st.Name, a.Type)
		}
	}
	return nil
}

// normalizeIfStep validates a type: if step: a parseable condition and at least
// one nested step, recursively normalized.
func normalizeIfStep(st *Step, depth int) error {
	if st.Condition == "" {
		return fmt.Errorf("step %q: type \"if\" requires a condition", st.Name)
	}
	cond, err := ParseCondition(st.Condition)
	if err != nil {
		return fmt.Errorf("step %q: %v", st.Name, err)
	}
	st.Cond = cond
	if len(st.Steps) == 0 {
		return fmt.Errorf("step %q: type \"if\" requires at least one nested step", st.Name)
	}
	for j := range st.Steps {
		n := &st.Steps[j]
		if n.Name == "" {
			n.Name = fmt.Sprintf("%s.%d", st.Name, j+1)
		}
		if err := normalizeStep(n, depth+1); err != nil {
			return err
		}
	}
	return normalizeControlFlow(st)
}

// normalizeControlFlow validates and defaults the control-flow fields shared by
// every step kind (think_time, retries, retry_backoff, on_error, stop_on_status).
func normalizeControlFlow(st *Step) error {
	if st.ThinkTime < 0 {
		return fmt.Errorf("step %q: think_time must be non-negative, got %v", st.Name, st.ThinkTime)
	}
	if st.Retries < 0 {
		return fmt.Errorf("step %q: retries must be non-negative, got %d", st.Name, st.Retries)
	}
	if st.RetryBackoff < 0 {
		return fmt.Errorf("step %q: retry_backoff must be non-negative, got %v", st.Name, st.RetryBackoff)
	}
	if st.OnError == "" {
		st.OnError = "stop"
	}
	switch st.OnError {
	case "continue", "stop":
	default:
		return fmt.Errorf("step %q: on_error must be \"continue\" or \"stop\", got %q", st.Name, st.OnError)
	}
	lower, upper, err := parseStatusMatcher(st.StopOnStatus)
	if err != nil {
		return fmt.Errorf("step %q: %v", st.Name, err)
	}
	st.StopStatusLower, st.StopStatusUpper = lower, upper
	return nil
}

func Load(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sc := &Scenario{}
	if err := yaml.Unmarshal(data, sc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := sc.Normalize(); err != nil {
		return nil, err
	}
	return sc, nil
}

func LoadJSON(data []byte) (*Scenario, error) {
	sc := &Scenario{}
	if err := json.Unmarshal(data, sc); err != nil {
		return nil, err
	}
	if err := sc.Normalize(); err != nil {
		return nil, err
	}
	return sc, nil
}
