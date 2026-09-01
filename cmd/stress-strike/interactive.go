package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
)

// ── ANSI color codes ──────────────────────────────────────────────────────

const (
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiRed   = "\x1b[31m"
	ansiGreen = "\x1b[32m"
	ansiCyan  = "\x1b[36m"
	ansiReset = "\x1b[0m"
)

// ── Wizard errors ─────────────────────────────────────────────────────────

var errCanceled = errors.New("setup canceled")

// ── Wizard tuning constants ───────────────────────────────────────────────

const (
	maxTotalUsers     = 100_000
	maxDurationSecs   = 7 * 24 * 60 * 60
	maxTimeoutSecs    = 300
	maxCaptureEntries = 100
	suggestedBurst    = 100_000
	politePublicRPS   = 50
	guidedLocalUsers  = 50
	guidedLocalDur    = 15
	guidedRemoteUsers = 25
	guidedRemoteDur   = 30
)

// ── Wizard types ──────────────────────────────────────────────────────────

type profileOption struct {
	key  string
	name string
	desc string
}

var profileOptions = []profileOption{
	{"1", config.ProfileSteady, "constant load for the whole run"},
	{"2", config.ProfileSoak, "steady load for long endurance runs"},
	{"3", config.ProfileLinearRamp, "grow linearly from low to peak load"},
	{"4", config.ProfileSpike, "sudden burst after a short baseline"},
	{"5", config.ProfileWave, "sinusoidal oscillation, mimics daily traffic"},
}

type wizardAnswers struct {
	name        string
	url         string
	method      string
	data        string
	headers     headerFlags
	profile     string
	users       int
	duration    int
	rampUp      int
	spikeUsers  int
	spikeWarmup int
	spikeHold   int
	wavePeriod  int
	rps         int
	timeout     int
	keepAlive   bool
	capture     int
	gate        bool
}

type lastRun struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

var historyFilePath = defaultHistoryPath

// ── Wizard persistence helpers ────────────────────────────────────────────

func defaultHistoryPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "stress-strike", "last-run.json")
}

func loadLastRun() lastRun {
	path := historyFilePath()
	if path == "" {
		return lastRun{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return lastRun{}
	}
	var r lastRun
	if json.Unmarshal(data, &r) != nil {
		return lastRun{}
	}
	return r
}

func saveLastRun(r lastRun) {
	path := historyFilePath()
	if path == "" || r.URL == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// ── Wizard struct and constructor ─────────────────────────────────────────

type wizard struct {
	in    *bufio.Reader
	out   io.Writer
	color bool
}

func newWizard(in io.Reader, out io.Writer, color bool) *wizard {
	return &wizard{in: bufio.NewReader(in), out: out, color: color}
}

// ── Wizard output helpers ─────────────────────────────────────────────────

func (w *wizard) paint(code, s string) string {
	if !w.color {
		return s
	}
	return code + s + ansiReset
}

func (w *wizard) printf(format string, a ...any) {
	fmt.Fprintf(w.out, format, a...)
}

func (w *wizard) errorf(format string, a ...any) {
	w.printf("%s\n", w.paint(ansiRed, "  ✗ "+fmt.Sprintf(format, a...)))
}

func joinNote(note string) string {
	if note == "" {
		return ""
	}
	return " (" + note + ")"
}

// ── Wizard input helpers ──────────────────────────────────────────────────

func (w *wizard) ask(prompt, def, note string) (string, error) {
	label := w.paint(ansiBold, prompt)
	if def != "" {
		label += " " + w.paint(ansiDim, "["+def+"]")
	}
	if note != "" {
		label += w.paint(ansiDim+ansiCyan, joinNote(note))
	}
	w.printf("%s: ", label)

	line, rerr := w.in.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return "", errCanceled
			}
			return "", fmt.Errorf("read input: %w", rerr)
		}
		return def, nil
	}
	return line, nil
}

func (w *wizard) readLine(prompt string) (string, error) {
	w.printf("%s", w.paint(ansiDim, prompt))
	line, rerr := w.in.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" && rerr != nil && !errors.Is(rerr, io.EOF) {
		return "", fmt.Errorf("read input: %w", rerr)
	}
	return line, nil
}

func (w *wizard) askInt(prompt string, def, min, max int, note string) (int, error) {
	for {
		raw, err := w.ask(prompt, strconv.Itoa(def), note)
		if err != nil {
			return 0, err
		}
		n, perr := strconv.Atoi(raw)
		if perr != nil || n < min || (max > 0 && n > max) {
			w.errorf("enter a number between %d and %s", min, limitLabel(max))
			continue
		}
		return n, nil
	}
}

func limitLabel(max int) string {
	if max > 0 {
		return strconv.Itoa(max)
	}
	return "unbounded"
}

func (w *wizard) askBool(prompt string, def bool, note string) (bool, error) {
	hint := "Y/n"
	if !def {
		hint = "y/N"
	}
	for {
		raw, err := w.ask(prompt, hint, note)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(raw) {
		case strings.ToLower(hint):
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			w.errorf("answer y or n")
		}
	}
}

// ── URL / name helpers ────────────────────────────────────────────────────

func normalizeTargetURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("target URL is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid URL %q", raw)
	}
	return raw, nil
}

func defaultTestName(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "quick-test"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(u.Hostname()) {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		return "quick-test"
	}
	return name
}

// ── Profile / mode choice parsers ─────────────────────────────────────────

func parseProfileChoice(sel string) (string, error) {
	sel = strings.ToLower(strings.TrimSpace(sel))
	if sel == "" {
		return config.ProfileSteady, nil
	}
	for _, opt := range profileOptions {
		if sel == opt.key || sel == opt.name {
			return opt.name, nil
		}
	}
	return "", fmt.Errorf("unknown profile %q (enter 1-5 or a profile name)", sel)
}

type setupMode int

const (
	modeGuided setupMode = iota
	modeExpert
	modeBeast
)

func parseModeChoice(sel string) (setupMode, error) {
	sel = strings.ToLower(strings.TrimSpace(sel))
	switch sel {
	case "", "1", "guided":
		return modeGuided, nil
	case "2", "expert":
		return modeExpert, nil
	case "3", "beast":
		return modeBeast, nil
	default:
		return modeGuided, fmt.Errorf("unknown mode %q (enter 1-3)", sel)
	}
}

func isLocalHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}

// ── Auto-tune presets ─────────────────────────────────────────────────────

func autoTune(target string) wizardAnswers {
	u, err := url.Parse(target)
	host := ""
	if err == nil {
		host = u.Hostname()
	}
	ans := wizardAnswers{
		url:       target,
		method:    "GET",
		headers:   headerFlags{},
		profile:   config.ProfileSteady,
		users:     guidedRemoteUsers,
		duration:  guidedRemoteDur,
		timeout:   10,
		keepAlive: true,
		rps:       politePublicRPS,
	}
	if isLocalHost(host) {
		ans.users = guidedLocalUsers
		ans.duration = guidedLocalDur
		ans.timeout = 5
		ans.rps = 0
	}
	return ans
}

func autoTuneBeast(target string) wizardAnswers {
	return wizardAnswers{
		url:       target,
		method:    "GET",
		headers:   headerFlags{},
		profile:   config.ProfileLinearRamp,
		users:     maxTotalUsers,
		duration:  300,
		rampUp:    240,
		timeout:   3,
		keepAlive: true,
		rps:       0,
	}
}

// ── Terminal detection ────────────────────────────────────────────────────

// isInteractiveTerminal reports whether stdin is a TTY (interactive user)
// as opposed to piped/redirected input (scripts, CI).
func isInteractiveTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// stdinIsTerminal is an alias for isInteractiveTerminal kept for backward
// compatibility with callers that use the origin/main naming.
func stdinIsTerminal() bool {
	return isInteractiveTerminal()
}

func stdoutIsColorable() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ── Wizard flow methods ───────────────────────────────────────────────────

func (w *wizard) askTargetURL(def lastRun) (string, error) {
	note := ""
	urlDef := ""
	if def.URL != "" {
		urlDef = def.URL
		note = "enter reuses your last target"
	}
	for {
		rawURL, err := w.ask("Target URL", urlDef, note)
		if err != nil {
			return "", err
		}
		target, nerr := normalizeTargetURL(rawURL)
		if nerr != nil {
			w.errorf("%v", nerr)
			continue
		}
		return target, nil
	}
}

func (w *wizard) askSetupMode() (setupMode, error) {
	w.printf("%s\n", w.paint(ansiBold, "Setup mode"))
	w.printf("  %s) %-8s %s%s\n", "1", w.paint(ansiGreen, "guided"), w.paint(ansiDim, "just give a URL — everything else auto-tuned"), w.paint(ansiCyan, "  ← recommended"))
	w.printf("  %s) %-8s %s\n", "2", w.paint(ansiGreen, "expert"), w.paint(ansiDim, "control every option yourself"))
	w.printf("  %s) %-8s %s\n", "3", w.paint(ansiRed, "beast"), w.paint(ansiDim, "maximum aggression — all limits pushed"))

	for {
		sel, err := w.ask("Select mode", "1", "recommended")
		if err != nil {
			return modeGuided, err
		}
		mode, perr := parseModeChoice(sel)
		if perr != nil {
			w.errorf("%v", perr)
			continue
		}
		return mode, nil
	}
}

func (w *wizard) askLoadProfile() (string, error) {
	w.printf("%s\n", w.paint(ansiBold, "Load profile"))
	for _, opt := range profileOptions {
		rec := ""
		if opt.name == config.ProfileSteady {
			rec = w.paint(ansiCyan, "  ← recommended")
		}
		w.printf("  %s) %-12s %s%s\n", opt.key, w.paint(ansiGreen, opt.name), w.paint(ansiDim, opt.desc), rec)
	}
	for {
		sel, err := w.ask("Select profile", "1", "recommended")
		if err != nil {
			return "", err
		}
		profile, perr := parseProfileChoice(sel)
		if perr != nil {
			w.errorf("%v", perr)
			continue
		}
		return profile, nil
	}
}

func (w *wizard) expertFlow(ans *wizardAnswers) error {
	method, err := w.ask("HTTP method", "GET", "recommended")
	if err != nil {
		return err
	}
	ans.method = strings.ToUpper(method)

	if ans.method != "GET" {
		body, err := w.ask("Request body", "", "")
		if err != nil {
			return err
		}
		ans.data = body
	}

	w.printf("%s\n", w.paint(ansiBold, "Request headers (Key=Value, empty line to finish)"))
	for {
		line, err := w.readLine("  > ")
		if err != nil {
			return err
		}
		if line == "" {
			break
		}
		if err := ans.headers.Set(line); err != nil {
			w.errorf("%v", err)
		}
	}

	users, err := w.askInt("Virtual users", 10, 1, maxTotalUsers, "recommended")
	if err != nil {
		return err
	}
	ans.users = users

	duration, err := w.askInt("Duration in seconds", 30, 1, maxDurationSecs, "recommended")
	if err != nil {
		return err
	}
	ans.duration = duration

	profile, err := w.askLoadProfile()
	if err != nil {
		return err
	}
	ans.profile = profile

	switch ans.profile {
	case config.ProfileLinearRamp:
		ramp, err := w.askInt("Ramp-up in seconds", duration/2, 0, 0, "auto")
		if err != nil {
			return err
		}
		ans.rampUp = ramp
	case config.ProfileSpike:
		burstDefault := users * 10
		if burstDefault < 0 || burstDefault > suggestedBurst {
			burstDefault = suggestedBurst
		}
		spikeUsers, err := w.askInt("Burst users", burstDefault, 1, maxTotalUsers, "auto")
		if err != nil {
			return err
		}
		ans.spikeUsers = spikeUsers
		warmup, err := w.askInt("Baseline warmup in seconds", 5, 0, maxDurationSecs, "auto")
		if err != nil {
			return err
		}
		ans.spikeWarmup = warmup
		hold, err := w.askInt("Burst hold in seconds", duration, 1, maxDurationSecs, "auto")
		if err != nil {
			return err
		}
		ans.spikeHold = hold
	case config.ProfileWave:
		period, err := w.askInt("Oscillation period in seconds", 0, 0, 0, "auto")
		if err != nil {
			return err
		}
		ans.wavePeriod = period
	}

	rps, err := w.askInt("RPS cap (0 = unlimited)", 0, 0, 0, "recommended")
	if err != nil {
		return err
	}
	ans.rps = rps

	timeout, err := w.askInt("Per-request timeout in seconds", 5, 1, maxTimeoutSecs, "recommended")
	if err != nil {
		return err
	}
	ans.timeout = timeout

	keepAlive, err := w.askBool("Reuse connections (keep-alive)", true, "recommended")
	if err != nil {
		return err
	}
	ans.keepAlive = keepAlive

	capN, err := w.askInt("Capture responses for debugging (0 = off)", 0, 0, maxCaptureEntries, "debug")
	if err != nil {
		return err
	}
	ans.capture = capN

	gateStrike, err := w.askBool("Gate strike — simultaneous race shot", false, "advanced")
	if err != nil {
		return err
	}
	ans.gate = gateStrike

	name, err := w.ask("Test name", defaultTestName(ans.url), "")
	if err != nil {
		return err
	}
	ans.name = name
	return nil
}

func (w *wizard) renderSummary(ans *wizardAnswers, mode setupMode) {
	w.printf("\n%s\n", w.paint(ansiBold, "Summary"))
	setup := "expert"
	tunedFor := ""
	switch mode {
	case modeGuided:
		setup = "guided (auto-tuned)"
		tunedFor = "a public API (polite limits)"
		u, err := url.Parse(ans.url)
		if err == nil && isLocalHost(u.Hostname()) {
			tunedFor = "local development (full power)"
		}
	case modeBeast:
		setup = "BEAST (maximum aggression)"
	}
	rows := [][2]string{
		{"Setup", setup},
		{"Target", ans.url},
		{"Method", ans.method},
		{"Profile", ans.profile},
		{"Users", strconv.Itoa(ans.users)},
		{"Duration", strconv.Itoa(ans.duration) + "s"},
	}
	switch ans.profile {
	case config.ProfileLinearRamp:
		rows = append(rows, [2]string{"Ramp-up", strconv.Itoa(ans.rampUp) + "s"})
	case config.ProfileSpike:
		rows = append(rows,
			[2]string{"Burst users", strconv.Itoa(ans.spikeUsers)},
			[2]string{"Spike window", fmt.Sprintf("%ds warmup + %ds hold", ans.spikeWarmup, ans.spikeHold)},
		)
	case config.ProfileWave:
		period := "auto"
		if ans.wavePeriod > 0 {
			period = strconv.Itoa(ans.wavePeriod) + "s"
		}
		rows = append(rows, [2]string{"Wave period", period})
	}
	rows = append(rows,
		[2]string{"RPS cap", rpsLabel(ans.rps)},
		[2]string{"Timeout", strconv.Itoa(ans.timeout) + "s"},
		[2]string{"Keep-alive", yesNo(ans.keepAlive)},
		[2]string{"Name", ans.name},
	)
	for _, row := range rows {
		w.printf("  %-*s %s\n", 14, w.paint(ansiDim, row[0]), row[1])
	}
	if mode == modeGuided {
		w.printf("\n%s\n", w.paint(ansiDim, "Settings chosen automatically for "+tunedFor+"."))
		w.printf("%s\n", w.paint(ansiDim, "Want full control? Re-run and pick 'expert'."))
	}
	if mode == modeBeast {
		w.printf("\n%s\n", w.paint(ansiRed, "⚠  BEAST MODE: maximum load generation."))
		w.printf("%s\n", w.paint(ansiRed, "   Run ONLY against systems you own or have written permission to test."))
	}
}

// runWizard launches the full guided setup wizard and returns the user's
// chosen test parameters.
func runWizard(in io.Reader, out io.Writer, color bool) (*wizardAnswers, error) {
	w := newWizard(in, out, color)

	w.printf("\n%s\n", w.paint(ansiBold+ansiCyan, "⚡ stress-strike — Interactive Setup"))
	w.printf("%s\n", w.paint(ansiDim, "Press Enter to accept [recommended]. Ctrl+C to cancel."))
	w.printf("%s\n\n", w.paint(ansiDim, "Only test systems you own or have permission to test."))

	last := loadLastRun()

	mode, err := w.askSetupMode()
	if err != nil {
		return nil, err
	}

	var ans wizardAnswers
	ans.headers = headerFlags{}

	ans.url, err = w.askTargetURL(last)
	if err != nil {
		return nil, err
	}

	switch mode {
	case modeGuided:
		ans = autoTune(ans.url)
		ans.headers = headerFlags{}
		ans.name = defaultTestName(ans.url)
	case modeBeast:
		ans = autoTuneBeast(ans.url)
		ans.name = "beast-" + defaultTestName(ans.url)
	default:
		if err := w.expertFlow(&ans); err != nil {
			return nil, err
		}
	}

	w.renderSummary(&ans, mode)

	confirmDef := true
	confirmNote := "recommended"
	if mode == modeBeast {
		confirmDef = false
		confirmNote = "type y deliberately — this is maximum load"
	}
	confirmed, err := w.askBool("\nStart test", confirmDef, confirmNote)
	if err != nil {
		return nil, err
	}
	if !confirmed {
		return nil, errCanceled
	}

	saveLastRun(lastRun{Name: ans.name, URL: ans.url})
	return &ans, nil
}

// ── Display helpers ───────────────────────────────────────────────────────

func rpsLabel(rps int) string {
	if rps == 0 {
		return "unlimited"
	}
	return strconv.Itoa(rps)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ── Interactive picker (LOCAL PRIMARY) ────────────────────────────────────

// interactivePicker presents the workspace selection menu when the binary is
// run with no arguments from a terminal: choose CLI (terminal report) or
// Web Server (real-time dashboard), then gather the minimum settings and run.
func interactivePicker() {
	r := bufio.NewReader(os.Stdin)

	banner()
	fmt.Println()
	fmt.Println("Choose a workspace:")
	fmt.Println()
	fmt.Println("  1) CLI    — run a load test and print a report to the terminal")
	fmt.Println("  2) Web    — start the real-time dashboard and run from the browser")
	fmt.Println("  3) Wizard — guided setup with auto-tuning (recommended for new users)")
	fmt.Println("  0) Quit")
	fmt.Println()

	choice := strings.TrimSpace(readLine(r, "Select [1/2/3/0]"))

	switch choice {
	case "2", "web", "server", "dashboard":
		interactiveDashboard(r)
	case "3", "wiz", "wizard":
		interactiveWizard(r)
	case "0", "q", "quit", "exit":
		fmt.Println("Bye.")
		os.Exit(0)
	default:
		interactiveCLI(r)
	}
}

// interactiveDashboard starts the real-time Web Server dashboard. It builds a
// default scenario from the answered settings, launches the dashboard server
// and the real engine; the user drives it from the browser.
func interactiveDashboard(r *bufio.Reader) {
	url := readLine(r, "Target URL (e.g. https://api.example.com)")
	if url == "" {
		fmt.Println("error: target URL is required.")
		os.Exit(1)
	}
	users := readInt(r, "Virtual users", 10)
	duration := readInt(r, "Duration (seconds)", 30)
	listen := readLine(r, "Dashboard listen address (e.g. :8888)")
	if listen == "" {
		listen = ":8888"
	}

	sc, err := quickScenario("interactive", url, "GET", "", headerFlags{},
		"steady", users, duration, 0, 0, 0, 0, 0, 0, 0, 5, true)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("\nStarting Web Server dashboard on %s — open it in a browser and press Start.\n\n", listen)
	runWithDashboard(sc, listen, "./reports")
}

// interactiveCLI gathers settings on the command line, then runs the real load
// engine and prints the terminal report.
func interactiveCLI(r *bufio.Reader) {
	fmt.Println()
	fmt.Println("Load test configuration (CLI mode):")
	fmt.Println()

	url := readLine(r, "Target URL (e.g. https://api.example.com)")
	if url == "" {
		fmt.Println("error: target URL is required.")
		os.Exit(1)
	}
	users := readInt(r, "Virtual users", 10)
	duration := readInt(r, "Duration (seconds)", 30)

	fmt.Println("\nRunning load test...")

	sc, err := quickScenario("interactive", url, "GET", "", headerFlags{},
		"steady", users, duration, 0, 0, 0, 0, 0, 0, 0, 5, true)
	if err != nil {
		fatal(err)
	}

	eng, err := engine.New(sc)
	if err != nil {
		fatal(err)
	}

	progress := engine.NewProgressTracker(
		time.Duration(sc.Profile.TotalDuration())*time.Second,
		sc.Profile.Users,
	)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tr, err := eng.Run(ctx, engine.RunOptions{Out: os.Stderr, Progress: progress})
	if err != nil {
		fatal(err)
	}
	if progress != nil {
		progress.Finish()
	}

	rpt := report.Build(tr, sc)
	rpt.Render(os.Stdout)

	jp, err := rpt.SaveJSON("./reports")
	if err == nil {
		tp, _ := rpt.SaveTXT("./reports")
		fmt.Fprintf(os.Stderr, "\nReports written:\n  %s\n", jp)
		if tp != "" {
			fmt.Fprintf(os.Stderr, "  %s\n", tp)
		}
	}
}

// interactiveWizard launches the full guided setup wizard (from origin/main),
// then executes the resulting test scenario in CLI mode. This bridges the
// wizard's richer interactive experience into the local primary run flow.
func interactiveWizard(r *bufio.Reader) {
	fmt.Println()
	fmt.Println("Launch the guided setup wizard:")
	fmt.Println()

	ans, err := runWizard(r, os.Stderr, stdoutIsColorable())
	if err != nil {
		if errors.Is(err, errCanceled) {
			fmt.Fprintln(os.Stderr, "Setup canceled.")
			return
		}
		fatal(err)
	}

	fmt.Println("\nRunning load test...")

	sc, err := quickScenario(ans.name, ans.url, ans.method, ans.data, ans.headers,
		ans.profile, ans.users, ans.duration, ans.rampUp, ans.spikeUsers, ans.spikeWarmup,
		ans.spikeHold, ans.wavePeriod, ans.rps, 0, ans.timeout, ans.keepAlive)
	if err != nil {
		fatal(err)
	}

	if ans.gate {
		sc.Profile.Gate = true
	}

	fmt.Fprintln(os.Stderr, "WARNING: stress-strike is a load testing tool. Only run it against systems you own or")
	fmt.Fprintln(os.Stderr, "have explicit written permission to test. Unauthorized load floods are illegal (DDoS).")

	warnLowFileLimit(sc.Profile)

	eng, err := engine.New(sc)
	if err != nil {
		fatal(err)
	}

	progress := engine.NewProgressTracker(
		time.Duration(sc.Profile.TotalDuration())*time.Second,
		sc.Profile.Users,
	)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tr, err := eng.Run(ctx, engine.RunOptions{Out: os.Stderr, Progress: progress})
	if err != nil {
		fatal(err)
	}
	if progress != nil {
		progress.Finish()
	}

	rpt := report.Build(tr, sc)
	rpt.Render(os.Stdout)

	jp, err := rpt.SaveJSON("./reports")
	if err == nil {
		tp, _ := rpt.SaveTXT("./reports")
		fmt.Fprintf(os.Stderr, "\nReports written:\n  %s\n", jp)
		if tp != "" {
			fmt.Fprintf(os.Stderr, "  %s\n", tp)
		}
	}
}

// ── Free-form input helpers (LOCAL PRIMARY) ───────────────────────────────

// readLine prompts the user and returns their trimmed input.
func readLine(r *bufio.Reader, prompt string) string {
	fmt.Printf("  %s: ", prompt)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimSpace(line)
}

func readInt(r *bufio.Reader, prompt string, def int) int {
	for {
		fmt.Printf("  %s [%d]: ", prompt, def)
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		if err == nil {
			n, e := strconv.Atoi(line)
			if e == nil {
				return n
			}
		}
		fmt.Println("    Invalid number, try again.")
	}
}

func banner() {
	fmt.Println("┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│           stress-strike — Load Testing Suite           │")
	fmt.Printf("│                     version %-10s                │\n", version)
	fmt.Println("└─────────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("WARNING: Only test systems you own or have explicit permission to test.")
	fmt.Println("         Unauthorized load testing is illegal (DDoS).")
}
