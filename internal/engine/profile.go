package engine

import (
	"fmt"
	"math"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
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

// waveProfile ramps virtual users up and down following a sine wave with the
// configured period, oscillating between a low and the full user count.
type waveProfile struct {
	users  int
	period time.Duration
	dur    time.Duration
}

// ConcurrencyAt returns the number of active users at the given elapsed time.
func (p *waveProfile) ConcurrencyAt(elapsed time.Duration) int {
	phase := 2 * math.Pi * float64(elapsed) / float64(p.period)
	n := int(float64(p.users) * (0.5 + 0.5*math.Sin(phase)))
	if n < 1 {
		n = 1
	}
	return n
}

func (p *waveProfile) MaxConcurrency() int {
	return p.users
}

func (p *waveProfile) Duration() time.Duration {
	return p.dur
}

// constantRPSProfile drives a fixed number of virtual users whose throughput
// is gated by a token-bucket rate limiter, not by concurrency scaling.
// Ramp-up linearly increases the bucket rate from 0 to targetRPS.
type constantRPSProfile struct {
	targetRPS int
	ramp      time.Duration
	dur       time.Duration
}

func newConstantRPSProfile(targetRPS int, rampUpSec int, dur time.Duration) *constantRPSProfile {
	ramp := time.Duration(rampUpSec) * time.Second
	if ramp <= 0 {
		ramp = dur / 2
		if ramp < time.Second {
			ramp = time.Second
		}
	}
	return &constantRPSProfile{
		targetRPS: targetRPS,
		ramp:      ramp,
		dur:       dur,
	}
}

// ConcurrencyAt returns a fixed worker count derived from the target RPS.
// Workers are plentiful; the token bucket is the actual throttle.
func (p *constantRPSProfile) ConcurrencyAt(_ time.Duration) int {
	return p.targetRPS
}

// TargetRPSAt returns the instantaneous RPS target at the given elapsed time.
// During ramp-up it scales linearly from 0 to targetRPS.
func (p *constantRPSProfile) TargetRPSAt(elapsed time.Duration) int {
	if p.ramp <= 0 || elapsed >= p.ramp {
		return p.targetRPS
	}
	rps := int(float64(p.targetRPS) * elapsed.Seconds() / p.ramp.Seconds())
	if rps < 1 {
		rps = 1
	}
	return rps
}

func (p *constantRPSProfile) MaxConcurrency() int {
	return p.targetRPS
}

func (p *constantRPSProfile) Duration() time.Duration {
	return p.dur
}

// IsConstantRPS reports whether this profile uses RPS-based targeting.
func (p *constantRPSProfile) IsConstantRPS() bool {
	return true
}

// RampDuration returns the ramp-up window.
func (p *constantRPSProfile) RampDuration() time.Duration {
	return p.ramp
}

func buildProfile(profile config.Profile) (LoadProfile, error) {
	dur := time.Duration(profile.Duration) * time.Second
	switch profile.Type {
	case config.ProfileSteady, config.ProfileSoak:
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
	case config.ProfileWave:
		return &waveProfile{
			users:  profile.Users,
			period: time.Duration(profile.WavePeriod) * time.Second,
			dur:    dur,
		}, nil
	case config.ProfileConstantRPS:
		return newConstantRPSProfile(profile.TargetRPS, profile.RampUp, dur), nil
	default:
		return nil, fmt.Errorf("unsupported load profile %q", profile.Type)
	}
}
