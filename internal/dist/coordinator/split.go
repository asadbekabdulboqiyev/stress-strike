package coordinator

import "github.com/asadbekabdulboqiyev/stress-strike/internal/config"

// share splits total across n workers, giving the first `total%n` workers one
// extra unit so the shares always sum back to total.
func share(total, index, n int) int {
	if n <= 0 || total <= 0 {
		return 0
	}
	base := total / n
	if index < total%n {
		return base + 1
	}
	return base
}

// SplitScenario derives the slice of the workload a single worker is
// responsible for. Every load-shaping field is divided — not just Users — so
// ramp, spike and constant-RPS profiles keep their aggregate shape across the
// fleet. Steps and variables are shared verbatim.
func SplitScenario(base *config.Scenario, index, total int) *config.Scenario {
	if base == nil {
		return nil
	}
	sc := *base
	sc.Profile = base.Profile
	sc.Profile.Users = share(base.Profile.Users, index, total)
	sc.Profile.SpikeUsers = share(base.Profile.SpikeUsers, index, total)
	sc.Profile.RPS = share(base.Profile.RPS, index, total)
	sc.Profile.TargetRPS = share(base.Profile.TargetRPS, index, total)

	sc.Steps = make([]config.Step, len(base.Steps))
	copy(sc.Steps, base.Steps)

	if base.Variables != nil {
		sc.Variables = make(map[string]string, len(base.Variables))
		for k, v := range base.Variables {
			sc.Variables[k] = v
		}
	}
	return &sc
}

// SplitUsers is the user-only share, kept for callers that only need the count.
func SplitUsers(users, index, total int) int {
	return share(users, index, total)
}
