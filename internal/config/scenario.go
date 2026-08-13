package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ProfileSteady     = "steady"
	ProfileLinearRamp = "linear-ramp"
	ProfileSpike      = "spike"
	maxUsers          = 100_000
)

type Profile struct {
	Type        string `yaml:"type" json:"type"`
	Users       int    `yaml:"users" json:"users"`
	Duration    int    `yaml:"duration" json:"duration"`
	RampUp      int    `yaml:"ramp_up" json:"ramp_up"`
	SpikeUsers  int    `yaml:"spike_users" json:"spike_users"`
	SpikeWarmup int    `yaml:"spike_warmup" json:"spike_warmup"`
	SpikeHold   int    `yaml:"spike_hold" json:"spike_hold"`
	RPS         int    `yaml:"rps" json:"rps"`
	Timeout     int    `yaml:"timeout" json:"timeout"`
	KeepAlive   *bool  `yaml:"keep_alive" json:"keep_alive"`
}

type Extract struct {
	Name string `yaml:"name" json:"name"`
	From string `yaml:"from" json:"from"`
	Path string `yaml:"path" json:"path"`
}

type Step struct {
	Name    string            `yaml:"name" json:"name"`
	Method  string            `yaml:"method" json:"method"`
	URL     string            `yaml:"url" json:"url"`
	Headers map[string]string `yaml:"headers" json:"headers"`
	Body    string            `yaml:"body" json:"body"`
	Extract []Extract         `yaml:"extract" json:"extract"`
	Timeout int               `yaml:"timeout" json:"timeout"`
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
	case ProfileSteady, ProfileLinearRamp, ProfileSpike:
	default:
		return fmt.Errorf("unsupported load profile %q (use: %s, %s, %s)", p.Type, ProfileSteady, ProfileLinearRamp, ProfileSpike)
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
	if p.RampUp <= 0 {
		p.RampUp = p.Duration / 2
		if p.RampUp < 1 {
			p.RampUp = 1
		}
	}
	if p.Timeout <= 0 {
		p.Timeout = 5
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
		if p.SpikeHold <= 0 {
			p.SpikeHold = p.Duration
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
		st.Method = strings.ToUpper(strings.TrimSpace(st.Method))
		if st.Method == "" {
			st.Method = "GET"
		}
		if st.URL == "" {
			return fmt.Errorf("step %q: url is required", st.Name)
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
