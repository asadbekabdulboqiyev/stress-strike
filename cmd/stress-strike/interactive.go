package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"stress-strike/internal/config"
)

const (
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiRed   = "\x1b[31m"
	ansiGreen = "\x1b[32m"
	ansiCyan  = "\x1b[36m"
	ansiReset = "\x1b[0m"
)

var errCanceled = errors.New("setup canceled")

const (
	maxTotalUsers     = 100_000
	maxDurationSecs   = 7 * 24 * 60 * 60
	maxTimeoutSecs    = 300
	suggestedBurst    = 100_000
	politePublicRPS   = 50
	guidedLocalUsers  = 50
	guidedLocalDur    = 15
	guidedRemoteUsers = 25
	guidedRemoteDur   = 30
)

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
}

type lastRun struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

var historyFilePath = defaultHistoryPath

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

type wizard struct {
	in    *bufio.Reader
	out   io.Writer
	color bool
}

func newWizard(in io.Reader, out io.Writer, color bool) *wizard {
	return &wizard{in: bufio.NewReader(in), out: out, color: color}
}

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

func parseModeChoice(sel string) (bool, error) {
	sel = strings.ToLower(strings.TrimSpace(sel))
	switch sel {
	case "", "1", "guided":
		return true, nil
	case "2", "expert":
		return false, nil
	default:
		return false, fmt.Errorf("unknown mode %q (enter 1 or 2)", sel)
	}
}

func isLocalHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}

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

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
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

func (w *wizard) askSetupMode() (bool, error) {
	w.printf("%s\n", w.paint(ansiBold, "Setup mode"))
	w.printf("  %s) %-8s %s%s\n", "1", w.paint(ansiGreen, "guided"), w.paint(ansiDim, "just give a URL — everything else auto-tuned"), w.paint(ansiCyan, "  ← recommended"))
	w.printf("  %s) %-8s %s\n", "2", w.paint(ansiGreen, "expert"), w.paint(ansiDim, "control every option yourself"))

	for {
		sel, err := w.ask("Select mode", "1", "recommended")
		if err != nil {
			return false, err
		}
		guided, perr := parseModeChoice(sel)
		if perr != nil {
			w.errorf("%v", perr)
			continue
		}
		return guided, nil
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

	name, err := w.ask("Test name", defaultTestName(ans.url), "")
	if err != nil {
		return err
	}
	ans.name = name
	return nil
}

func (w *wizard) renderSummary(ans *wizardAnswers, guided bool) {
	w.printf("\n%s\n", w.paint(ansiBold, "Summary"))
	setup := "expert"
	tunedFor := ""
	if guided {
		setup = "guided (auto-tuned)"
		tunedFor = "a public API (polite limits)"
		u, err := url.Parse(ans.url)
		if err == nil && isLocalHost(u.Hostname()) {
			tunedFor = "local development (full power)"
		}
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
	if guided {
		w.printf("\n%s\n", w.paint(ansiDim, "Settings chosen automatically for "+tunedFor+"."))
		w.printf("%s\n", w.paint(ansiDim, "Want full control? Re-run and pick 'expert'."))
	}
}

func runWizard(in io.Reader, out io.Writer, color bool) (*wizardAnswers, error) {
	w := newWizard(in, out, color)

	w.printf("\n%s\n", w.paint(ansiBold+ansiCyan, "⚡ stress-strike — Interactive Setup"))
	w.printf("%s\n", w.paint(ansiDim, "Press Enter to accept [recommended]. Ctrl+C to cancel."))
	w.printf("%s\n\n", w.paint(ansiDim, "Only test systems you own or have permission to test."))

	last := loadLastRun()

	guided, err := w.askSetupMode()
	if err != nil {
		return nil, err
	}

	var ans wizardAnswers
	ans.headers = headerFlags{}

	ans.url, err = w.askTargetURL(last)
	if err != nil {
		return nil, err
	}

	if guided {
		ans = autoTune(ans.url)
		ans.headers = headerFlags{}
		ans.name = defaultTestName(ans.url)
	} else {
		if err := w.expertFlow(&ans); err != nil {
			return nil, err
		}
	}

	w.renderSummary(&ans, guided)

	confirmed, err := w.askBool("\nStart test", true, "recommended")
	if err != nil {
		return nil, err
	}
	if !confirmed {
		return nil, errCanceled
	}

	saveLastRun(lastRun{Name: ans.name, URL: ans.url})
	return &ans, nil
}

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
