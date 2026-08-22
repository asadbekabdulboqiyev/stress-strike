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
	ProfileSteady     = "steady"
	ProfileSoak       = "soak"
	ProfileLinearRamp = "linear-ramp"
	ProfileSpike      = "spike"
	ProfileWave       = "wave"
	maxUsers          = 100_000
	maxDuration       = 7 * 24 * 60 * 60 // 7 days, in seconds
	maxTimeout        = 5 * 60           // 5 minutes, in seconds
)

type Profile struct {
	Type        string `yaml:"type" json:"type"`
	Users       int    `yaml:"users" json:"users"`
	Duration    int    `yaml:"duration" json:"duration"`
	RampUp      int    `yaml:"ramp_up" json:"ramp_up"`
	SpikeUsers  int    `yaml:"spike_users" json:"spike_users"`
	SpikeWarmup int    `yaml:"spike_warmup" json:"spike_warmup"`
	SpikeHold   int    `yaml:"spike_hold" json:"spike_hold"`
	WavePeriod  int    `yaml:"wave_period" json:"wave_period"`
	RPS         int    `yaml:"rps" json:"rps"`
	Timeout     int    `yaml:"timeout" json:"timeout"`
	KeepAlive   *bool  `yaml:"keep_alive" json:"keep_alive"`
	WAFEnabled  bool   `yaml:"waf_enabled" json:"waf_enabled"`
	RateLimitConfig `yaml:"rate_limit" json:"rate_limit"`
}

type Extract struct {
	Name string `yaml:"name" json:"name"`
	From string `yaml:"from" json:"from"`
	Path string `yaml:"path" json:"path"`
}

type RateLimitConfig struct {
	DefaultRPS   int        `yaml:"default_rps" json:"default_rps"`
	MaxBurst     int        `yaml:"max_burst" json:"max_burst"`
	IPRPS        int        `yaml:"ip_rps" json:"ip_rps"`
	IPBurst      int        `yaml:"ip_burst" json:"ip_burst"`
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
}

type Scenario struct {
	Name      string            `yaml:"name" json:"name"`
	BaseURL   string            `yaml:"base_url" json:"base_url"`
	Profile   Profile           `yaml:"load_profile" json:"load_profile"`
	Steps     []Step            `yaml:"steps" json:"steps"`
	Variables map[string]string `yaml:"variables" json:"variables"`
}

func (p *Profile) Normalize() error {
	if p.Type == "" {
		p.Type = ProfileSteady
	}
	switch p.Type {
	case ProfileSteady, ProfileSoak, ProfileLinearRamp, ProfileSpike, ProfileWave:
	default:
		return fmt.Errorf("unsupported load profile %q (use: %s, %s, %s, %s, %s)", p.Type, ProfileSteady, ProfileSoak, ProfileLinearRamp, ProfileSpike, ProfileWave)
	}
	if p.Users < 1 {
		p.Users = 10
	}
	if p.Users > maxUsers {
		return fmt.Errorf("users (%d) exceeds maximum of %d", p.Users, maxUsers)
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

func (s *Scenario) Normalize() error {
	if s.Name == "" {
		s.Name = "unnamed"
	}
	if err := s.Profile.Normalize(); err != nil {
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
