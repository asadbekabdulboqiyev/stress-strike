package dashboard

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

// defaultDemoStoreURL is where the bundled VoltStore demo listens by default
// (examples/demo_store serves 127.0.0.1:8090 unless a custom -addr is given).
const defaultDemoStoreURL = "http://127.0.0.1:8090"

// demoStoreReadyTimeout bounds how long Start waits for the store to accept
// connections. A cold `go run` fallback has to compile first, so this is
// generous (browsers time out much later).
const demoStoreReadyTimeout = 15 * time.Second

// DemoStore supervises the bundled VoltStore demo target. It locates the
// demo-store binary, spawns it (with VeriGate protection ON so the dashboard
// always demonstrates the protected target), and tracks liveness so the UI
// can offer a one-click "open the demo" button whose state stays honest.
//
// If a store is already listening on the address — started by the user, the
// SLA script, or a previous dashboard session — it is adopted as "running"
// but never killed by Stop (we only terminate processes we spawned).
type DemoStore struct {
	mu      sync.Mutex
	url     string
	cmd     *exec.Cmd
	managed bool // we spawned the process, so Stop may kill it
	protect bool // protection flag used at launch
	logger  *log.Logger
}

// NewDemoStore creates a launcher/supervisor for the VoltStore demo.
func NewDemoStore(logger *log.Logger) *DemoStore {
	if logger == nil {
		logger = log.Default()
	}
	return &DemoStore{url: defaultDemoStoreURL, logger: logger}
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

// Status returns a snapshot for the control API.
func (d *DemoStore) Status() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	return map[string]any{
		"url":        d.url,
		"running":    d.Running(),
		"managed":    d.managed,
		"protection": d.managed && d.protect,
	}
}

// locate finds a way to run the demo store, preferring a pre-built binary,
// then a binary on PATH, then a `go run` inside a checkout of this repo.
// The checkout search walks upward from the working directory, so the
// dashboard works from any subdirectory of the repo — not just the root.
func (d *DemoStore) locate() (string, []string, error) {
	// 1) Pre-built binary in a checkout: ./bin/demo-store (make build).
	if p := findUp("bin/demo-store"); p != "" {
		return p, nil, nil
	}
	// 2) A demo-store binary on PATH (installed alongside stress-strike).
	if p, err := exec.LookPath("demo-store"); err == nil {
		return p, nil, nil
	}
	// 3) Go checkout: `go run ./examples/demo_store` (needs a toolchain).
	if root := findUp("go.mod"); root != "" {
		if _, err := os.Stat(filepath.Join(root, "examples", "demo_store")); err == nil {
			if goBin, err := exec.LookPath("go"); err == nil {
				return goBin, []string{"run", filepath.Join(root, "examples", "demo_store")}, nil
			}
		}
	}
	return "", nil, fmt.Errorf(
		"demo store not found: build it with `make build` (bin/demo-store), install it on PATH, or run the dashboard from the stress-strike checkout")
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

	bin, extra, err := d.locate()
	if err != nil {
		return "", false, err
	}
	// The dashboard always launches the store with VeriGate protection ON:
	// the whole point is to demo the WAF. Visitors can still flip it OFF
	// from the store's own /admin control plane.
	args := append(append([]string{}, extra...), "-protect")
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &prefixedLineWriter{prefix: "[demo-store] ", logger: d.logger}
	cmd.Stderr = &prefixedLineWriter{prefix: "[demo-store] ", logger: d.logger}
	if err := cmd.Start(); err != nil {
		return "", false, fmt.Errorf("start demo store: %w", err)
	}
	d.cmd = cmd
	d.managed = true
	d.protect = true

	// A single goroutine reaps the process (no zombies), signalling exit so
	// the readiness loop below can distinguish "slow to boot" from "died".
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()

	deadline := time.Now().Add(demoStoreReadyTimeout)
	for {
		if d.Running() {
			return d.url, false, nil
		}
		select {
		case <-exited:
			d.cmd = nil
			d.managed = false
			d.protect = false
			return "", false, fmt.Errorf("demo store exited during startup (see [demo-store] log above)")
		case <-time.After(150 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			break
		}
	}
	_ = cmd.Process.Kill()
	d.cmd = nil
	d.managed = false
	d.protect = false
	return "", false, fmt.Errorf("demo store did not become ready within %s", demoStoreReadyTimeout)
}

// Stop terminates the store only when the dashboard spawned it. A store that
// was already running (user-managed) is left untouched. The reaper goroutine
// from Start owns the wait, so we only signal the process here.
func (d *DemoStore) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.managed || d.cmd == nil || d.cmd.Process == nil {
		return nil
	}
	_ = d.cmd.Process.Kill()
	d.cmd = nil
	d.managed = false
	d.protect = false
	return nil
}

// prefixedLineWriter forwards subprocess output to the dashboard log with a
// stable prefix, one line at a time (demo-store already logs complete lines).
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
