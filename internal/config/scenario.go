package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ProfileSteady      = "steady"
	ProfileSoak        = "soak"
	ProfileLinearRamp  = "linear-ramp"
	ProfileSpike       = "spike"
	ProfileWave        = "wave"
	ProfileConstantRPS = "constant-rps"
	maxUsers           = 100_000
	maxRPS             = 1_000_000
	maxDuration        = 7 * 24 * 60 * 60 // 7 days, in seconds
	maxTimeout         = 5 * 60           // 5 minutes, in seconds
)

type Profile struct {
	Type            string `yaml:"type" json:"type"`
	Users           int    `yaml:"users" json:"users"`
	Duration        int    `yaml:"duration" json:"duration"`
	RampUp          int    `yaml:"ramp_up" json:"ramp_up"`
	SpikeUsers      int    `yaml:"spike_users" json:"spike_users"`
	SpikeWarmup     int    `yaml:"spike_warmup" json:"spike_warmup"`
	SpikeHold       int    `yaml:"spike_hold" json:"spike_hold"`
	WavePeriod      int    `yaml:"wave_period" json:"wave_period"`
	RPS             int    `yaml:"rps" json:"rps"`
	TargetRPS       int    `yaml:"target_rps" json:"target_rps"`
	Timeout         int    `yaml:"timeout" json:"timeout"`
	KeepAlive       *bool  `yaml:"keep_alive" json:"keep_alive"`
	WAFEnabled      bool   `yaml:"waf_enabled" json:"waf_enabled"`
	RateLimitConfig `yaml:"rate_limit" json:"rate_limit"`
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
	Type       string            `yaml:"type" json:"type"` // http (default) | ws | grpc | tcp | udp
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
	AwaitResponse bool   `yaml:"await_response" json:"await_response"` // udp: wait for a reply and measure RTT
	Session       bool   `yaml:"session" json:"session"`               // ws|tcp: keep one persistent connection per virtual user
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
	switch p.Type {
	case ProfileSteady, ProfileSoak, ProfileLinearRamp, ProfileSpike, ProfileWave, ProfileConstantRPS:
	default:
		return fmt.Errorf("unsupported load profile %q (use: %s, %s, %s, %s, %s, %s)", p.Type, ProfileSteady, ProfileSoak, ProfileLinearRamp, ProfileSpike, ProfileWave, ProfileConstantRPS)
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
		st.Type = strings.ToLower(strings.TrimSpace(st.Type))
		if st.Type == "" {
			st.Type = "http"
		}
		switch st.Type {
		case "http", "ws", "grpc", "tcp", "udp":
		default:
			return fmt.Errorf("step %q: unsupported type %q (use http, ws, grpc, tcp, udp)", st.Name, st.Type)
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
		if st.Timeout > maxTimeout {
			return fmt.Errorf("step %q: timeout (%d) exceeds maximum of %d seconds (%d minutes)", st.Name, st.Timeout, maxTimeout, maxTimeout/60)
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
	}
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
