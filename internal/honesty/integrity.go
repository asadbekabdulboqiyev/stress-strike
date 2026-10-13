package honesty

// integrity.go — the pacing bookkeeping and the coordinated-omission (CO)
// correction, in exact integer arithmetic.
//
// # Coordinated omission
//
// A paced load generator aims to send request number k at
//
//	intended_start(k) = window_start + k / rps
//
// In nanoseconds that is window_start + k * 1e12 / rps_milli, where rps_milli
// is the rate expressed in thousandths of a request per second (so "1000.000"
// is 1_000_000). When the target slows down, the generator is itself blocked
// waiting for responses and the next request is sent *late*; the naive
// measurement records only the fast service time and silently discards the
// waiting time — the coordinated-omission bug.
//
// VeriBench's correction is exact and reproducible: for each record, the honest
// latency is
//
//	corrected = latency + max(0, start_ns - intended_start(seq))
//
// The slot index is seq-1, not the record's position in the file, so a worker
// that dropped a scheduled request keeps the schedule gap visible instead of
// compressing it away.
//
// # Pacing bookkeeping
//
// PlannedSlots and ScheduleAccuracyPPM let a verifier recompute, from the
// planned rate and duration alone, how many request slots the run intended and
// how far the achieved rate drifted. Because these are pure functions of values
// already inside the bundle, the integrity block can be checked structurally,
// even when the raw sidecar is not present.

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
)

// PPMScale is 100% in parts per million; it is exported because bundle readers
// need it to interpret schedule_accuracy_ppm.
const PPMScale = ppmScale

// nsPerSecond is the number of nanoseconds in a second.
const nsPerSecond = 1_000_000_000

// milliScale is the number of thousandths in a unit (rates are decimal values
// with three fractional digits).
const milliScale = 1_000

// mulDivFloor returns floor(a*b/d) with a 128-bit intermediate. It errors on a
// zero divisor or on overflow instead of wrapping.
func mulDivFloor(a, b, d uint64) (uint64, error) {
	if d == 0 {
		return 0, errors.New("honesty: division by zero")
	}
	hi, lo := bits.Mul64(a, b)
	if hi >= d {
		return 0, fmt.Errorf("honesty: %d*%d/%d overflows 64 bits", a, b, d)
	}
	q, _ := bits.Div64(hi, lo, d)
	return q, nil
}

// mulDivRound returns a*b/d rounded half away from zero, erroring on overflow.
func mulDivRound(a, b, d uint64) (uint64, error) {
	if d == 0 {
		return 0, errors.New("honesty: division by zero")
	}
	hi, lo := bits.Mul64(a, b)
	lo, carry := bits.Add64(lo, d/2, 0)
	hi += carry
	if hi >= d {
		return 0, fmt.Errorf("honesty: %d*%d/%d overflows 64 bits", a, b, d)
	}
	q, _ := bits.Div64(hi, lo, d)
	return q, nil
}

// mulDivRoundU is mulDivRound for call sites whose inputs are provably bounded
// (the confidence-interval math). It returns 0 instead of erroring, so it can
// never panic; the bound is asserted by construction at each call site.
func mulDivRoundU(a, b, d uint64) uint64 {
	q, err := mulDivRound(a, b, d)
	if err != nil {
		return 0
	}
	return q
}

// AchievedRPSMilli returns the measured request rate in thousandths of a
// request per second: count requests over durationNS nanoseconds, scaled by
// 1e3. It errors on a non-positive duration or on overflow.
func AchievedRPSMilli(count uint64, durationNS int64) (int64, error) {
	if durationNS <= 0 {
		return 0, fmt.Errorf("honesty: duration_ns %d must be positive", durationNS)
	}
	// count / (durationNS / 1e9) * 1e3 = count * 1e12 / durationNS.
	milli, err := mulDivRound(count, nsPerSecond*milliScale, uint64(durationNS))
	if err != nil {
		return 0, err
	}
	if milli > math.MaxInt64 {
		return 0, errors.New("honesty: achieved rate overflows int64")
	}
	return int64(milli), nil
}

// PlannedSlots returns how many request slots a paced run intended to fill:
// round(planned_rps * duration_s). plannedMilli is the planned rate in
// thousandths of a request per second.
func PlannedSlots(plannedMilli int64, durationNS int64) (uint64, error) {
	if plannedMilli < 0 {
		return 0, fmt.Errorf("honesty: planned rate %d is negative", plannedMilli)
	}
	if durationNS <= 0 {
		return 0, fmt.Errorf("honesty: duration_ns %d must be positive", durationNS)
	}
	// plannedMilli/1e3 * durationNS/1e9 = plannedMilli * durationNS / 1e12.
	slots, err := mulDivRound(uint64(plannedMilli), uint64(durationNS), nsPerSecond*milliScale)
	if err != nil {
		return 0, err
	}
	return slots, nil
}

// DroppedSamples returns the number of intended slots that produced no sample:
// max(0, slots - count).
func DroppedSamples(plannedMilli int64, durationNS int64, count uint64) (uint64, error) {
	slots, err := PlannedSlots(plannedMilli, durationNS)
	if err != nil {
		return 0, err
	}
	if count >= slots {
		return 0, nil
	}
	return slots - count, nil
}

// ScheduleAccuracyPPM returns how closely the achieved rate tracked the planned
// rate, as parts per million: 1e6 means exact, 0 means off by 100% or more. A
// non-positive planned rate returns 1e6 when nothing was achieved and 0
// otherwise, so the function is total.
//
// The deviation is computed in unsigned arithmetic whose magnitude is exact
// even when the two rates sit at opposite ends of the int64 range, and a
// deviation too large to represent in 64 bits is reported as the minimum
// accuracy rather than the maximum: an unrepresentable miss is still a miss.
// Reporting perfect accuracy for a wildly wrong run would let the integrity
// block bless exactly the failures it exists to expose.
func ScheduleAccuracyPPM(plannedMilli, achievedMilli int64) int64 {
	if plannedMilli <= 0 {
		if achievedMilli <= 0 {
			return ppmScale
		}
		return 0
	}
	// Subtract in uint64 space: the difference of two int64 values always fits,
	// and the unsigned wrap-around yields the exact magnitude even when
	// achievedMilli is negative.
	var diff uint64
	if achievedMilli >= plannedMilli {
		diff = uint64(achievedMilli) - uint64(plannedMilli)
	} else {
		diff = uint64(plannedMilli) - uint64(achievedMilli)
	}
	deviation, err := mulDivRound(diff, uint64(ppmScale), uint64(plannedMilli))
	if err != nil || deviation >= uint64(ppmScale) {
		return 0
	}
	return int64(ppmScale) - int64(deviation)
}

// IntendedStartNS returns the wall-clock instant (Unix nanoseconds) at which
// slot seq was scheduled to begin, given the worker's window start and the
// planned rate. seq is 1-based; seq 0 means "before the first slot" and returns
// the window start.
//
// This is the exact schedule the producer used, so a verifier recomputes the
// same offsets and therefore the same corrected latencies.
func IntendedStartNS(windowStartNS int64, seq uint64, rpsMilli int64) (int64, error) {
	if rpsMilli <= 0 {
		return 0, fmt.Errorf("honesty: rps_milli %d must be positive", rpsMilli)
	}
	if windowStartNS < 0 {
		return 0, fmt.Errorf("honesty: window_start_ns %d is negative", windowStartNS)
	}
	slot := seq
	if slot > 0 {
		slot--
	}
	offset, err := mulDivRound(slot, nsPerSecond*milliScale, uint64(rpsMilli))
	if err != nil {
		return 0, err
	}
	if offset > math.MaxInt64 || windowStartNS > math.MaxInt64-int64(offset) {
		return 0, errors.New("honesty: intended start overflows int64")
	}
	return windowStartNS + int64(offset), nil
}

// CorrectedLatencyNS returns the coordinated-omission-corrected latency for a
// record: its raw latency plus any waiting time between its intended and actual
// start. When the request was sent on time the raw latency is returned
// unchanged.
func CorrectedLatencyNS(startNS, latencyNS int64, windowStartNS int64, seq uint64, rpsMilli int64) (int64, error) {
	if latencyNS < 0 {
		return 0, fmt.Errorf("honesty: latency_ns %d is negative", latencyNS)
	}
	intended, err := IntendedStartNS(windowStartNS, seq, rpsMilli)
	if err != nil {
		return 0, err
	}
	var wait int64
	if startNS > intended {
		wait = startNS - intended
	}
	if latencyNS > math.MaxInt64-wait {
		return 0, errors.New("honesty: corrected latency overflows int64")
	}
	return latencyNS + wait, nil
}
