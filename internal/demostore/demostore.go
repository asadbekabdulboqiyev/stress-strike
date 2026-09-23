// Package demostore supervises the bundled VoltStore demo target: it locates
// the demo-store binary, spawns it, and tracks liveness. It is shared by the
// web dashboard (one-click "open the demo" button) and the
// `stress-strike demo-store` CLI command, so both entry points behave
// identically and supervision logic stays in one place.
package demostore

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultURL is where the bundled VoltStore demo listens by default
// (examples/demo_store serves 127.0.0.1:8090 unless a custom -addr is given).
const DefaultURL = "http://127.0.0.1:8090"

// readyTimeout bounds how long Start waits for the store to accept
// connections. A cold `go run` fallback has to compile first, so this is
// generous (browsers time out much later).
const readyTimeout = 15 * time.Second

// killWait bounds how long Stop waits for the process to die after SIGKILL.
// Killed processes exit almost instantly; this is pure safety.
const killWait = 5 * time.Second

// Options configures a DemoStore.
type Options struct {
	// URL where the demo store listens. Empty means DefaultURL. It is what
	// Running probes and Start/Status report; when the store is spawned, the
	// caller normally passes the matching -addr flag inside ExtraArgs.
	URL string

	// ExtraArgs are appended to the spawned binary's command line (for
	// example "-protect" to enable VeriGate, or "-addr=127.0.0.1:8090").
	ExtraArgs []string

	// Logger receives subprocess output when the store was spawned. Nil
	// defaults to log.Default().
	Logger *log.Logger
}

// DemoStore supervises the bundled VoltStore demo target. It locates the
// demo-store binary, spawns it, and tracks liveness so callers can offer a
// one-click "open the demo" entry point whose state stays honest.
//
// If a store is already listening on the address — started by the user, the
// SLA script, or a previous session — it is adopted as "running" but never
// killed by Stop (we only terminate processes we spawned).
type DemoStore struct {
	mu      sync.Mutex
	url     string
	extra   []string
	cmd     *exec.Cmd
	exited  chan struct{} // closed by the reaper goroutine once the process is gone
	managed bool          // we spawned the process, so Stop may kill it
	protect bool          // protection flag used at launch
	logger  *log.Logger

	// locateOverride replaces locate() for tests (spawns a fake store).
	locateOverride func() (string, []string, error)
}

// New creates a launcher/supervisor for the VoltStore demo.
func New(opts Options) *DemoStore {
	url := opts.URL
	if url == "" {
		url = DefaultURL
	}
	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &DemoStore{url: url, extra: opts.ExtraArgs, logger: logger}
}

// URL returns the base URL of the demo store.
func (d *DemoStore) URL() string { return d.url }

// Running reports whether something is listening on the demo store address.
func (d *DemoStore) Running() bool {
	host := strings.TrimPrefix(d.url, "http://")
	host = strings.TrimPrefix(host, "https://")
	conn, err := net.DialTimeout("tcp", host, 300*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Status returns a snapshot for control APIs.
func (d *DemoStore) Status() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	// A spawned process that crashed is no longer "managed": the supervisor
	// does not hold a live process, and the Stop button must not claim one.
	managed := d.managed && !d.exitedClosed()
	return map[string]any{
		"url":        d.url,
		"running":    d.Running(),
		"managed":    managed,
		"protection": managed && d.protect,
	}
}

// exitedClosed reports whether the reaper goroutine has already reaped the
// spawned process. Must be called with d.mu held.
func (d *DemoStore) exitedClosed() bool {
	if d.exited == nil {
		return false
	}
	select {
	case <-d.exited:
		return true
	default:
		return false
	}
}

// Done returns a channel that is closed when the spawned store process
// exits. When no process is managed (adopted store, or nothing running) it
// returns a channel that never closes — callers should only rely on it after
// a successful Start that reported a fresh spawn.
func (d *DemoStore) Done() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.exited == nil {
		ch := make(chan struct{})
		return ch
	}
	return d.exited
}

// locate finds a way to run the demo store, preferring a pre-built binary,
// then a binary on PATH, then a `go run` inside a checkout of this repo.
// The checkout search walks upward from the working directory, so it works
// from any subdirectory of the repo — not just the root.
func (d *DemoStore) locate() (string, []string, error) {
	if d.locateOverride != nil {
		return d.locateOverride()
	}
	// 1) Pre-built binary in a checkout: ./bin/demo-store (make build).
	if p := findUp("bin/demo-store"); p != "" {
		return p, nil, nil
	}
	// 2) A demo-store binary on PATH (installed alongside stress-strike).
	if p, err := exec.LookPath("demo-store"); err == nil {
		return p, nil, nil
	}
	// 3) Go checkout: `go run ./examples/demo_store` (needs a toolchain).
	// findUp returns the go.mod FILE path — the checkout root is its parent.
	if mod := findUp("go.mod"); mod != "" {
		root := filepath.Dir(mod)
		if _, err := os.Stat(filepath.Join(root, "examples", "demo_store")); err == nil {
			if goBin, err := exec.LookPath("go"); err == nil {
				return goBin, []string{"run", filepath.Join(root, "examples", "demo_store")}, nil
			}
		}
	}
	return "", nil, fmt.Errorf(
		"demo store not found: build it with `make build` (bin/demo-store), install it on PATH, or run the command from the stress-strike checkout")
}

// findUp walks from the working directory toward the filesystem root looking
// for a relative path (e.g. "bin/demo-store" or "go.mod"), returning the
// absolute path of the first hit, or "" when nothing is found.
func findUp(rel string) string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(dir, rel)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// Start ensures the demo store is running, spawning it when nothing is
// listening yet. It returns the URL and whether the store was already up.
func (d *DemoStore) Start() (string, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.Running() {
		return d.url, true, nil
	}

	bin, runArgs, err := d.locate()
	if err != nil {
		return "", false, err
	}
	args := append(append([]string{}, runArgs...), d.extra...)
	cmd := exec.Command(bin, args...)
	spawnProcessGroup(cmd) // go run fallback: kill reaps the whole tree
	cmd.Stdout = &prefixedLineWriter{prefix: "[demo-store] ", logger: d.logger}
	cmd.Stderr = &prefixedLineWriter{prefix: "[demo-store] ", logger: d.logger}
	if err := cmd.Start(); err != nil {
		return "", false, fmt.Errorf("start demo store: %w", err)
	}
	d.cmd = cmd
	d.managed = true
	d.protect = hasProtect(d.extra)

	// A single goroutine reaps the process (no zombies), signalling exit so
	// the readiness loop below can distinguish "slow to boot" from "died".
	// clearSpawned is deliberately NOT called here: Start's readiness loop
	// holds the mutex while waiting on `exited`, so the reaper can never
	// take the lock itself (deadlock). Stop/Status detect the closed channel
	// via exitedClosed() instead.
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	d.exited = exited

	deadline := time.Now().Add(readyTimeout)
	for {
		if d.Running() {
			return d.url, false, nil
		}
		select {
		case <-exited:
			d.clearSpawned()
			return "", false, fmt.Errorf("demo store exited during startup (see [demo-store] log above)")
		case <-time.After(150 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			break
		}
	}
	killProcessGroup(cmd)
	d.clearSpawned()
	return "", false, fmt.Errorf("demo store did not become ready within %s", readyTimeout)
}

// hasProtect reports whether the spawn args enable VeriGate protection.
func hasProtect(args []string) bool {
	for _, a := range args {
		if a == "-protect" || strings.HasPrefix(a, "-protect=") {
			return true
		}
	}
	return false
}

// clearSpawned forgets a process we spawned. It must be called with d.mu
// held. The reaper goroutine owns the wait, so the process is never leaked.
func (d *DemoStore) clearSpawned() {
	d.cmd = nil
	d.exited = nil
	d.managed = false
	d.protect = false
}

// Stop terminates the store only when the dashboard spawned it. A store that
// was already running (user-managed) is left untouched. The reaper goroutine
// from Start owns the wait, so we only signal the process here — but we do
// block until it actually exits, so a closely following Start() cannot adopt
// the dying process as "already running" and lose supervision over it.
//
// A process that already crashed is NOT re-killed: its group is gone, and
// its PID (or group ID) may have been recycled by an unrelated process.
func (d *DemoStore) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.managed || d.cmd == nil || d.cmd.Process == nil {
		return nil
	}
	if !d.exitedClosed() {
		killProcessGroup(d.cmd)
		if d.exited != nil {
			select {
			case <-d.exited: // process reaped
			case <-time.After(killWait):
			}
		}
	}
	d.clearSpawned()
	return nil
}

// prefixedLineWriter forwards subprocess output to the log with a stable
// prefix, one line at a time (demo-store already logs complete lines).
type prefixedLineWriter struct {
	prefix string
	logger *log.Logger
}

func (w *prefixedLineWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimSuffix(string(p), "\n"), "\n") {
		if text := strings.TrimSpace(line); text != "" {
			w.logger.Printf("%s%s", w.prefix, text)
		}
	}
	return len(p), nil
}
