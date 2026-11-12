package report

// scoring_test.go — the contract for the shared score, grade and verdict
// ladders.
//
// These three functions are the only place a pentest result becomes a number,
// a letter and a sentence, and the CLI and the dashboard both call them. The
// tests below pin the arithmetic and every band boundary, because a boundary
// that moved by one point is exactly how the two entry points drifted before.

import (
	"strings"
	"testing"
)

func TestFindingPenaltyWeights(t *testing.T) {
	cases := []struct {
		name                 string
		crit, high, med, low int
		want                 int
	}{
		{"nothing found", 0, 0, 0, 0, 0},
		{"one critical", 1, 0, 0, 0, 25},
		{"one high", 0, 1, 0, 0, 15},
		{"one medium", 0, 0, 1, 0, 8},
		{"one low", 0, 0, 0, 1, 3},
		{"one of each", 1, 1, 1, 1, 51},
		{"two criticals", 2, 0, 0, 0, 50},
		{"criticals plus a high", 3, 1, 0, 0, 90},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FindingPenalty(c.crit, c.high, c.med, c.low); got != c.want {
				t.Errorf("FindingPenalty(%d,%d,%d,%d) = %d, want %d",
					c.crit, c.high, c.med, c.low, got, c.want)
			}
		})
	}
}

// TestFindingPenaltyCapsAt100 keeps a long finding list from producing a
// negative score. The cap is the whole score, so five criticals and fifty lows
// both bottom out at 0 rather than -350.
func TestFindingPenaltyCapsAt100(t *testing.T) {
	cases := []struct{ crit, high, med, low int }{
		{4, 0, 0, 0},         // exactly 100
		{5, 0, 0, 0},         // 125 -> 100
		{0, 0, 0, 50},        // 150 -> 100
		{100, 100, 100, 100}, // far past the cap
	}
	for _, c := range cases {
		if got := FindingPenalty(c.crit, c.high, c.med, c.low); got != 100 {
			t.Errorf("FindingPenalty(%d,%d,%d,%d) = %d, want the 100 cap",
				c.crit, c.high, c.med, c.low, got)
		}
	}
}

// TestFindingPenaltyNeverNegative covers a caller passing counts that add up
// to nothing or that were never populated.
func TestFindingPenaltyNeverNegative(t *testing.T) {
	if got := FindingPenalty(0, 0, 0, 0); got != 0 {
		t.Errorf("FindingPenalty(0,0,0,0) = %d, want 0", got)
	}
}

// TestGradeForScoreBands pins all six bands and both sides of every boundary.
// C+ exists so "fixed some of it" is distinguishable from "fixed none of it";
// 69 must be a C and 70 a C+, not the other way round.
func TestGradeForScoreBands(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{100, "A"},
		{90, "A"},
		{89, "B"},
		{80, "B"},
		{79, "C+"},
		{70, "C+"},
		{69, "C"},
		{60, "C"},
		{59, "D"},
		{50, "D"},
		{49, "F"},
		{1, "F"},
		{0, "F"},
	}

	for _, c := range cases {
		if got := GradeForScore(c.score); got != c.want {
			t.Errorf("GradeForScore(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

// TestVerdictForKeysOnSeverity documents the deliberate choice: the verdict is
// decided by the highest severity present, not by the score. A scan that
// tested four of ten categories can score 60 while holding a critical
// exposure, and the sentence must still say CRITICAL.
func TestVerdictForKeysOnSeverity(t *testing.T) {
	cases := []struct {
		name                 string
		crit, high, med, low int
		want                 string
	}{
		{"critical wins over everything", 1, 5, 5, 5, "CRITICAL RISK -- Immediate remediation required"},
		{"high without a critical", 0, 1, 5, 5, "HIGH RISK -- Urgent remediation recommended"},
		{"medium without high or critical", 0, 0, 1, 5, "MEDIUM RISK -- Remediation recommended"},
		{"only low", 0, 0, 0, 1, "LOW RISK -- Minor issues found"},
		{"nothing", 0, 0, 0, 0, "CLEAN -- No significant issues found"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := VerdictFor(c.crit, c.high, c.med, c.low); got != c.want {
				t.Errorf("VerdictFor(%d,%d,%d,%d) = %q, want %q",
					c.crit, c.high, c.med, c.low, got, c.want)
			}
		})
	}
}

// TestVerdictIsNeverCLEANWithFindings is the regression test for the drift
// that motivated the consolidation: the dashboard once counted only the
// structured finding list, so a scan whose OWASP findings held a critical
// exposure certified itself CLEAN. The shared ladder makes that impossible —
// any non-zero count produces a risk sentence.
func TestVerdictIsNeverCLEANWithFindings(t *testing.T) {
	for crit := 0; crit <= 2; crit++ {
		for high := 0; high <= 2; high++ {
			for med := 0; med <= 2; med++ {
				for low := 0; low <= 2; low++ {
					got := VerdictFor(crit, high, med, low)
					if crit+high+med+low > 0 && strings.HasPrefix(got, "CLEAN") {
						t.Errorf("VerdictFor(%d,%d,%d,%d) = %q with findings present",
							crit, high, med, low, got)
					}
				}
			}
		}
	}
}

// TestScoreBreakdownExplainsTheNumber keeps the dashboard's one-line
// explanation readable and arithmetically honest: the finding factor shown is
// 100 minus the penalty.
func TestScoreBreakdownExplainsTheNumber(t *testing.T) {
	got := ScoreBreakdown(60, 80, 8, 10, 2, 25, 3, "C")
	for _, want := range []string{"60/100", "8 of 10", "2 not tested", "75/100", "−25", "grade C"} {
		if !strings.Contains(got, want) {
			t.Errorf("ScoreBreakdown() = %q, missing %q", got, want)
		}
	}
}

// TestScoreBreakdownDerivesFromTheLadders proves the line agrees with the
// functions it describes: a complete assessment with one critical is the CLI's
// score, and its grade comes from GradeForScore.
func TestScoreBreakdownDerivesFromTheLadders(t *testing.T) {
	penalty := FindingPenalty(1, 0, 0, 0)
	score := 100 - penalty
	grade := GradeForScore(score)

	line := ScoreBreakdown(score, 100, 10, 10, 0, penalty, 1, grade)
	if !strings.Contains(line, "75/100") || !strings.Contains(line, "grade C+") {
		t.Errorf("complete assessment with one critical: %q, want 75/100 and grade C+", line)
	}
}
