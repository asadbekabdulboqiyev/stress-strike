package siem

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// parseRetryAfter interprets a Retry-After header value, which may be either a
// non-negative integer number of seconds or an HTTP-date. It returns the delay
// and whether the header was present and well-formed.
func parseRetryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}

	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}

	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0, true // already elapsed: retry immediately
		}
		return d, true
	}

	return 0, false
}
