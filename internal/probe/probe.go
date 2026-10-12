// Package probe implements the self-contained health probe used by container
// HEALTHCHECK instructions and Kubernetes exec probes.
//
// Distroless images ship no shell, wget or curl, so instead of shelling out
// each stress-strike binary can probe its own operations endpoint:
//
//	stress-strike-master healthcheck -addr http://127.0.0.1:9090/healthz
//	stress-strike-worker healthcheck -addr http://127.0.0.1:9091/healthz
//
// It exits 0 when the endpoint answers 2xx and 1 otherwise, which is exactly
// the contract Docker and Kubernetes expect from a health probe.
package probe

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// EnvURL is the environment variable that overrides the default probe target,
// so a single HEALTHCHECK instruction can serve every binary.
const EnvURL = "SS_HEALTH_URL"

// fallbackURL is used when neither -addr/-url nor SS_HEALTH_URL is set. It
// points at the master's default operations port.
const fallbackURL = "http://127.0.0.1:9090/healthz"

// UsageError is returned by Run for a malformed invocation (exit code 2).
const UsageError = 2

// DefaultURL returns the probe target from SS_HEALTH_URL, falling back to
// defaultURL (when non-empty) and finally the loopback master endpoint.
func DefaultURL(defaultURL string) string {
	if v := strings.TrimSpace(os.Getenv(EnvURL)); v != "" {
		return v
	}
	if strings.TrimSpace(defaultURL) != "" {
		return defaultURL
	}
	return fallbackURL
}

// Run parses args (the argv *after* the "healthcheck" subcommand), probes the
// endpoint and returns the process exit code:
//
//	0  endpoint answered 2xx (healthy)
//	1  connection error or non-2xx status (unhealthy)
//	2  usage error (bad flags / no address)
//
// defaultURL is the fallback used when neither -addr/-url nor SS_HEALTH_URL is
// supplied; pass "" to use the built-in master default.
func Run(args []string, defaultURL string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		addr    = fs.String("addr", DefaultURL(defaultURL), "URL to probe (2xx = healthy)")
		urlFlag = fs.String("url", "", "alias for -addr")
		timeout = fs.Float64("timeout", 3.0, "probe timeout in seconds")
	)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return UsageError
	}
	target := *addr
	if *urlFlag != "" {
		target = *urlFlag
	}
	target = strings.TrimSpace(target)
	if target == "" {
		fmt.Fprintln(os.Stderr, "healthcheck: no address to probe")
		return UsageError
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	return Get(target, time.Duration(*timeout*float64(time.Second)))
}

// Get performs a single GET request and maps the result to an exit code.
func Get(url string, timeout time.Duration) int {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url) //nolint:gosec // probe target is operator-supplied by design
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %s: %v\n", url, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "healthcheck: %s: status %s\n", url, resp.Status)
		return 1
	}
	return 0
}
