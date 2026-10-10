// Package version is the single source of truth for build metadata.
//
// All values are overridden at link time by GoReleaser, the Makefile and the
// Dockerfiles:
//
//	go build -ldflags "\
//	  -X github.com/asadbekabdulboqiyev/stress-strike/internal/version.Version=0.14.3 \
//	  -X github.com/asadbekabdulboqiyev/stress-strike/internal/version.Commit=af13f15 \
//	  -X github.com/asadbekabdulboqiyev/stress-strike/internal/version.Date=2026-10-01T00:00:00Z"
//
// Keeping this in one package (instead of a per-main `var version`) means all
// six binaries report the same value and a forgotten ldflag degrades to "dev"
// instead of silently printing a stale hardcoded number.
package version

import "runtime/debug"

var (
	// Version is the semantic version, e.g. "0.14.3". Overridden at link time.
	Version = "dev"

	// Commit is the git commit SHA the binary was built from.
	Commit = ""

	// Date is the RFC3339 build timestamp.
	Date = ""
)

// Full returns "version (commit, date)" suitable for --version output.
// Values not injected at link time are read from the embedded VCS stamp that
// the Go toolchain records when -buildvcs is left enabled.
func Full() string {
	v, c, d := Version, Commit, Date

	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if c == "" {
					c = s.Value
				}
			case "vcs.time":
				if d == "" {
					d = s.Value
				}
			}
		}
	}

	out := v
	if c != "" {
		if len(c) > 12 {
			c = c[:12]
		}
		out += " (" + c
		if d != "" {
			out += ", " + d
		}
		out += ")"
	}
	if v == "dev" {
		out += " [unofficial build]"
	}
	return out
}
