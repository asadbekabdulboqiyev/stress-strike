package report

// ANSI 16-color escape codes.
const (
	colorReset  = "\x1b[0m"
	colorBold   = "\x1b[1m"
	colorRed    = "\x1b[31m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorCyan   = "\x1b[36m"
	colorWhite  = "\x1b[37m"
)

// colorize wraps s with the given ANSI escape when enabled is true.
func colorize(color string, enabled bool, s string) string {
	if !enabled {
		return s
	}
	return color + s + colorReset
}

// rateColor returns the ANSI color code appropriate for the given error rate.
//
//	0%   -> green
//	<5%  -> yellow
//	>=5% -> red
func rateColor(errorPct float64) string {
	switch {
	case errorPct <= 0:
		return colorGreen
	case errorPct < 5:
		return colorYellow
	default:
		return colorRed
	}
}

// statusColor returns a color for an HTTP status code family.
func statusColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return colorGreen
	case code >= 300 && code < 400:
		return colorCyan
	case code >= 400 && code < 500:
		return colorYellow
	default:
		return colorRed
	}
}

// healthLabel returns a verdict and its color based on error rate.
func healthLabel(errorPct float64) (string, string) {
	switch {
	case errorPct <= 0:
		return "HEALTHY", colorGreen
	case errorPct < 5:
		return "DEGRADED", colorYellow
	default:
		return "CRITICAL", colorRed
	}
}
