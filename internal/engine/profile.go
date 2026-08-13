package engine

import (
	"fmt"
	"time"

	"stress-strike/internal/config"
)

type LoadProfile interface {
	ConcurrencyAt(elapsed time.Duration) int
	MaxConcurrency() int
	Duration() time.Duration
}

type steadyProfile struct {
	users int
	dur   time.Duration
}

func (p *steadyProfile) ConcurrencyAt(_ time.Duration) int {
	return p.users
}

func (p *steadyProfile) MaxConcurrency() int {
	return p.users
}

func (p *steadyProfile) Duration() time.Duration {
	return p.dur
}

type rampProfile struct {
	users int
	ramp  time.Duration
	dur   time.Duration
}

func (p *rampProfile) ConcurrencyAt(elapsed time.Duration) int {
	if elapsed >= p.ramp || p.ramp <= 0 {
		return p.users
	}
	n := int(float64(elapsed) / float64(p.ramp) * float64(p.users))
	if n < 1 {
		n = 1
	}
	return n
}

func (p *rampProfile) MaxConcurrency() int {
	return p.users
}

func (p *rampProfile) Duration() time.Duration {
	return p.dur
}

type spikeProfile struct {
	baseline   int
	spikeUsers int
	warmup     time.Duration
	hold       time.Duration
}

func (p *spikeProfile) ConcurrencyAt(elapsed time.Duration) int {
	if elapsed < p.warmup {
		return p.baseline
	}
	if elapsed < p.warmup+p.hold {
		return p.spikeUsers
	}
	return p.baseline
}

func (p *spikeProfile) MaxConcurrency() int {
	if p.spikeUsers > p.baseline {
		return p.spikeUsers
	}
	return p.baseline
}

func (p *spikeProfile) Duration() time.Duration {
	return p.warmup + p.hold
}

func buildProfile(profile config.Profile) (LoadProfile, error) {
	dur := time.Duration(profile.Duration) * time.Second
	switch profile.Type {
	case config.ProfileSteady:
		return &steadyProfile{users: profile.Users, dur: dur}, nil
	case config.ProfileLinearRamp:
		return &rampProfile{
			users: profile.Users,
			ramp:  time.Duration(profile.RampUp) * time.Second,
			dur:   dur,
		}, nil
	case config.ProfileSpike:
		return &spikeProfile{
			baseline:   profile.Users,
			spikeUsers: profile.SpikeUsers,
			warmup:     time.Duration(profile.SpikeWarmup) * time.Second,
			hold:       time.Duration(profile.SpikeHold) * time.Second,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported load profile %q", profile.Type)
	}
}
