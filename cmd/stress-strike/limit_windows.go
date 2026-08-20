//go:build windows

package main

import "stress-strike/internal/config"

// warnLowFileLimit is a no-op on Windows: there is no ulimit / RLIMIT_NOFILE
// concept, so no open-file guard is possible or necessary.
func warnLowFileLimit(profile config.Profile) {}
