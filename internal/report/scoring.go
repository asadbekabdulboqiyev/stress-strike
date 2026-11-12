package report

// scoring.go — the one place a pentest result becomes a number, a letter and a
// sentence.
//
// These three ladders used to be written twice: once in cmd_pentest_report.go
// for the shell, once in internal/dashboard/pentest_certificate.go for the
// browser. They drifted, and the drift was not cosmetic — the dashboard said
// "CLEAN -- No significant issues found" on a scan that had found a critical
// exposure, because only one of the two copies had ever been taught to look at
// the merged finding list. A shared source of truth is the only way the two
// entry points cannot disagree about the same scan again.

import "fmt"

// Severity weights. A critical finding costs 25 points, a high 15, a medium 8
// and a low 3. They are deliberately harsh: this tool exists to stop an
// operator shipping a critical exposure, so the score must move when one is
// found.
const (
	PenaltyCritical = 25
	PenaltyHigh     = 15
	PenaltyMedium   = 8
	PenaltyLow      = 3
)

// FindingPenalty is the total score cost of the findings, capped at 100 so a
// long list of low findings cannot drag the arithmetic below zero.
func FindingPenalty(critical, high, medium, low int) int {
	penalty := critical*PenaltyCritical + high*PenaltyHigh + medium*PenaltyMedium + low*PenaltyLow
	if penalty < 0 {
		return 0
	}
	if penalty > 100 {
		return 100
	}
	return penalty
}

// GradeForScore maps a 0-100 score onto the letter grade a report shows.
//
// There are six bands, not five: C+ exists so a result that fixed some of what
// a previous run found can be told apart from one that fixed none of it. The
// ladder is shared by the CLI and the dashboard, so 69 is a C in both.
func GradeForScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C+"
	case score >= 60:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

// VerdictFor is the one-sentence judgement printed above the findings.
//
// It keys on the highest severity present, not on the score: a scan that
// covered four of ten categories can score 60 while holding a critical
// exposure, and the sentence must say CRITICAL, not "medium risk".
func VerdictFor(critical, high, medium, low int) string {
	switch {
	case critical > 0:
		return "CRITICAL RISK -- Immediate remediation required"
	case high > 0:
		return "HIGH RISK -- Urgent remediation recommended"
	case medium > 0:
		return "MEDIUM RISK -- Remediation recommended"
	case low > 0:
		return "LOW RISK -- Minor issues found"
	default:
		return "CLEAN -- No significant issues found"
	}
}

// ScoreBreakdown explains a dashboard score in one line, so the reader can see
// where the number came from instead of being asked to trust it. The CLI's
// report has no equivalent line because its coverage is always complete.
func ScoreBreakdown(score, coverage int, passed, total, untested, penalty, findings int, grade string) string {
	return fmt.Sprintf(
		"Score %d/100 = %d coverage points (%d of %d categories passed, %d not tested) "+
			"× %d/100 finding factor (%d finding(s), −%d points) → grade %s.",
		score, coverage, passed, total, untested, 100-penalty, findings, penalty, grade)
}
