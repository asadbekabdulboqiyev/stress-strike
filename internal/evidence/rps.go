package evidence

import "github.com/asadbekabdulboqiyev/stress-strike/internal/config"

// milliPerRPS converts a rate in requests per second into the thousandths-of-a-
// request-per-second unit the bundle format uses.
//
// This constant exists because getting it wrong is invisible: a producer that
// forgot the factor of 1000 would seal a claim of "0.3 requests per second" for
// a 300 rps run, and every verifier would still pass — the verifier recomputes
// the correction from the same rate, so a self-consistent lie verifies. The
// result is not a detected tamper, it is nonsense statistics published with a
// valid signature. Only the honesty direction assertion in the tests catches
// this class of mistake, which is why it is asserted there.
const milliPerRPS = 1000

// PlannedRPSMilli is the rate a scenario intended to sustain, in thousandths of
// a request per second, or 0 when the run was unpaced.
//
// constant-rps mode paces directly at target_rps; any profile can be capped
// with a global rps limit. When both are set the direct pace wins, because that
// is the schedule the engine actually follows. An unpaced run returns 0, which
// is the honest answer: there was no schedule to keep, so there is nothing the
// coordinated-omission correction may be applied against.
func PlannedRPSMilli(scenario *config.Scenario) int64 {
	if scenario == nil {
		return 0
	}
	switch {
	case scenario.Profile.TargetRPS > 0:
		return int64(scenario.Profile.TargetRPS) * milliPerRPS
	case scenario.Profile.RPS > 0:
		return int64(scenario.Profile.RPS) * milliPerRPS
	default:
		return 0
	}
}
