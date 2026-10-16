package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// authzDeniedExitCode is returned when a run is blocked by the authorization
// policy. It is distinct from 1 (runtime error) and 2 (bad usage) so CI can
// tell "the tool broke" from "the policy refused".
const authzDeniedExitCode = 3

// gateOptions is the CLI surface of the authorization layer.
type gateOptions struct {
	policyPath   string
	auditPath    string
	webhook      string
	allowPrivate bool
	authorized   string
}

// addAuthzFlags registers the shared authorization flags on a FlagSet.
func addAuthzFlags(fs *flag.FlagSet, g *gateOptions) {
	fs.StringVar(&g.authorized, "authorized", "", "authorization ticket id granted by an approver (required for pentest)")
	fs.BoolVar(&g.allowPrivate, "allow-private", false, "allow RFC1918/private targets without an explicit authorization entry")
	fs.StringVar(&g.policyPath, "policy", "", "authorization policy JSON (default ~/.stress-strike/authz.json)")
	fs.StringVar(&g.auditPath, "audit-log", "", "append-only audit log path (default ~/.stress-strike/audit.jsonl)")
	fs.StringVar(&g.webhook, "notify-webhook", "", "webhook URL to notify on every authorization decision")
}

// configHome returns the directory holding stress-strike's local state.
// configHome, defaultPolicyPath and defaultAuditPath delegate to the authz
// package so the CLI, the scan binary and the dashboard resolve the same
// policy and the same audit trail. The bodies used to live here and in
// cmd/stress-strike-scan as two hand-kept copies.
func configHome() string {
	return authz.ConfigHome()
}

func defaultPolicyPath() string {
	return authz.DefaultPolicyPath()
}

func defaultAuditPath() string {
	return authz.DefaultAuditPath()
}

// authzOutcome is the aggregate verdict for a run.
type authzOutcome struct {
	Allowed bool
	Class   string
	Rule    string
	Reason  string
	Targets []string
	IPs     []string
}

// evaluateAuthz classifies every target and applies the policy. A denial is an
// outcome, not an error; error is reserved for infrastructure failures.
func evaluateAuthz(op authz.Operation, targets []string, g gateOptions) (authzOutcome, error) {
	policyPath := strings.TrimSpace(g.policyPath)
	if policyPath == "" {
		policyPath = defaultPolicyPath()
	}
	pol, err := authz.LoadPolicyOrDefault(policyPath)
	if err != nil {
		return authzOutcome{}, err
	}
	if g.allowPrivate {
		pol.AllowPrivate = true
	}
	if env := os.Getenv("STRESS_STRIKE_ALLOW"); env != "" {
		if err := pol.AddEnvRules(env); err != nil {
			return authzOutcome{}, err
		}
	}

	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := authzOutcome{Allowed: true, Targets: targets}
	worst := authz.ClassPublic

	for _, raw := range targets {
		tgt, err := authz.Classify(ctx, raw, nil)
		if err != nil {
			return authzOutcome{}, err
		}
		for _, ip := range tgt.IPs {
			out.IPs = append(out.IPs, ip.String())
		}
		worst = authz.Worst(worst, tgt.Class())

		var d authz.Decision
		switch {
		case op == authz.OpPentest:
			// Offensive operation: an approval entry must exist in the policy
			// AND the operator must name its ticket. Neither alone is enough.
			if strings.TrimSpace(g.authorized) == "" {
				d = authz.Decision{Class: tgt.Class(),
					Reason: fmt.Sprintf("pentest against %s requires --authorized <ticket> naming an entry approved with `authorize add`", tgt.Host)}
			} else if pat, ok := pol.AuthorizedBy(tgt, g.authorized, now); ok {
				d = authz.Decision{Allowed: true, Class: tgt.Class(), Rule: pat,
					Reason: fmt.Sprintf("authorization ticket %q (%s)", g.authorized, pat)}
			} else {
				d = authz.Decision{Class: tgt.Class(),
					Reason: fmt.Sprintf("no active authorization with ticket %q covers %s", g.authorized, tgt.Host)}
			}
		case strings.TrimSpace(g.authorized) != "":
			// The operator named a ticket: it must actually cover the target.
			if pat, ok := pol.AuthorizedBy(tgt, g.authorized, now); ok {
				d = authz.Decision{Allowed: true, Class: tgt.Class(), Rule: pat,
					Reason: fmt.Sprintf("authorization ticket %q (%s)", g.authorized, pat)}
			} else {
				d = authz.Decision{Class: tgt.Class(),
					Reason: fmt.Sprintf("no active authorization with ticket %q covers %s", g.authorized, tgt.Host)}
			}
		default:
			d = pol.Check(tgt, op, now)
		}

		if !d.Allowed {
			out.Allowed = false
			if out.Reason == "" {
				out.Reason = d.Reason
				out.Rule = d.Rule
			}
		} else if out.Rule == "" {
			out.Rule = d.Rule
			out.Reason = d.Reason
		}
	}
	out.Class = worst.String()
	return out, nil
}

// enforceAuthz gates a run: it classifies the targets, writes an audit record,
// and either returns or terminates with the denial exit code.
func enforceAuthz(op authz.Operation, targets []string, argv []string, g gateOptions) {
	if len(targets) == 0 {
		return
	}
	out, err := evaluateAuthz(op, targets, g)
	if err != nil {
		fatal(err)
	}

	recordAuthz(authz.Entry{
		Action:  op.String(),
		Targets: targets,
		IPs:     out.IPs,
		Class:   out.Class,
		Allowed: out.Allowed,
		Rule:    out.Rule,
		Reason:  out.Reason,
		Version: version,
		Argv:    argv,
	}, g.auditPath, g.webhook)

	if out.Allowed {
		if out.Rule != "" {
			fmt.Fprintf(os.Stderr, "authorization: ok (class=%s, rule=%s)\n", out.Class, out.Rule)
		} else {
			fmt.Fprintf(os.Stderr, "authorization: ok (class=%s)\n", out.Class)
		}
		return
	}

	fmt.Fprintf(os.Stderr, "\nBLOCKED by authorization policy\n")
	fmt.Fprintf(os.Stderr, "  target: %s\n", strings.Join(targets, ", "))
	fmt.Fprintf(os.Stderr, "  reason: %s\n\n", out.Reason)
	fmt.Fprintln(os.Stderr, "To authorize a test, have the approver add an entry:")
	fmt.Fprintln(os.Stderr, "  stress-strike authorize add --pattern <host-or-cidr> --approver <name> --ticket <id>")
	fmt.Fprintln(os.Stderr, "then re-run with --authorized <id>.")
	os.Exit(authzDeniedExitCode)
}

func recordAuthz(e authz.Entry, auditPath, webhook string) {
	if strings.TrimSpace(auditPath) == "" {
		auditPath = defaultAuditPath()
	}
	log, err := authz.Open(auditPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot write audit log: %v\n", err)
		return
	}
	stored, appendErr := log.Append(e)
	_ = log.Close()
	if appendErr != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot write audit log: %v\n", appendErr)
	}

	if strings.TrimSpace(webhook) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), authz.DefaultNotifyTimeout)
	defer cancel()
	if err := (authz.Notifier{URL: webhook}).Notify(ctx, stored); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit webhook failed: %v\n", err)
	}
}

func scenarioTargets(sc *config.Scenario) []string {
	if sc == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || !strings.Contains(u, "://") || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	add(sc.BaseURL)
	for _, s := range sc.Steps {
		add(s.URL)
	}
	return out
}

func runAuthorizeWithGate(sc *config.Scenario, op authz.Operation, g gateOptions) {
	enforceAuthz(op, scenarioTargets(sc), os.Args, g)
}

// ── CLI: authorize ──────────────────────────────────────────────────────────

func cmdAuthorize() {
	args := os.Args[2:]
	if len(args) == 0 {
		authorizeUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		authorizeAdd(args[1:])
	case "list", "ls":
		authorizeList(args[1:])
	case "remove", "rm":
		authorizeRemove(args[1:])
	case "verify":
		authorizeVerify(args[1:])
	case "help", "--help", "-h":
		authorizeUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown authorize subcommand %q\n\n", args[0])
		authorizeUsage()
		os.Exit(2)
	}
}

func authorizeUsage() {
	fmt.Fprint(os.Stderr, `usage: stress-strike authorize <add|list|remove|verify> [flags]

Authorization entries define which targets may be tested and by whose approval.
They are stored in `+defaultPolicyPath()+`.

  add     --pattern <host|*.domain|cidr|*> [--until RFC3339] [--approver NAME]
          [--ticket ID] [--reason TEXT] [--policy PATH]
  list    [--policy PATH]
  remove  --pattern <pattern> [--policy PATH]
  verify  [--policy PATH]
`)
}

func authorizeAdd(args []string) {
	fs := flag.NewFlagSet("authorize add", flag.ContinueOnError)
	pattern := fs.String("pattern", "", "target pattern: host, *.domain, CIDR, or *")
	until := fs.String("until", "", "expiry as RFC3339 (default: no expiry)")
	approver := fs.String("approver", "", "who approved this authorization")
	ticket := fs.String("ticket", "", "change/incident ticket id")
	reason := fs.String("reason", "", "why this target is authorized")
	policyPath := fs.String("policy", defaultPolicyPath(), "policy file")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if strings.TrimSpace(*pattern) == "" {
		fatal(fmt.Errorf("--pattern is required"))
	}

	r := authz.Rule{Pattern: strings.TrimSpace(*pattern), Approver: *approver, Ticket: *ticket, Reason: *reason}
	if *until != "" {
		ts, err := time.Parse(time.RFC3339, *until)
		if err != nil {
			fatal(fmt.Errorf("--until must be RFC3339: %w", err))
		}
		r.Until = ts
	}

	pol, err := authz.LoadPolicyOrDefault(*policyPath)
	if err != nil {
		fatal(err)
	}
	replaced := false
	for i := range pol.Rules {
		if pol.Rules[i].Pattern == r.Pattern {
			pol.Rules[i] = r
			replaced = true
			break
		}
	}
	if !replaced {
		pol.Rules = append(pol.Rules, r)
	}
	if err := savePolicy(*policyPath, pol); err != nil {
		fatal(err)
	}

	verb := "added"
	if replaced {
		verb = "updated"
	}
	fmt.Printf("%s authorization: %s", verb, r.Pattern)
	if !r.Until.IsZero() {
		fmt.Printf(" (until %s)", r.Until.Format(time.RFC3339))
	}
	if r.Ticket != "" {
		fmt.Printf(" ticket=%s", r.Ticket)
	}
	fmt.Printf("\npolicy: %s\n", *policyPath)
}

func authorizeList(args []string) {
	fs := flag.NewFlagSet("authorize list", flag.ContinueOnError)
	policyPath := fs.String("policy", defaultPolicyPath(), "policy file")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	pol, err := authz.LoadPolicyOrDefault(*policyPath)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("policy: %s\nmode: %s (allow_private=%v)\n", *policyPath, modeName(pol.Mode), pol.AllowPrivate)
	if len(pol.Rules) == 0 {
		fmt.Println("rules: (none)")
		return
	}
	now := time.Now()
	fmt.Println("rules:")
	for _, r := range pol.Rules {
		state := "active"
		if !r.Until.IsZero() && now.After(r.Until) {
			state = "EXPIRED " + r.Until.Format(time.RFC3339)
		} else if !r.Until.IsZero() {
			state = "until " + r.Until.Format(time.RFC3339)
		}
		fmt.Printf("  %-32s %-28s approver=%-14s ticket=%s\n", r.Pattern, state, orDash(r.Approver), orDash(r.Ticket))
	}
}

func authorizeRemove(args []string) {
	fs := flag.NewFlagSet("authorize remove", flag.ContinueOnError)
	pattern := fs.String("pattern", "", "pattern to remove")
	policyPath := fs.String("policy", defaultPolicyPath(), "policy file")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *pattern == "" {
		fatal(fmt.Errorf("--pattern is required"))
	}
	pol, err := authz.LoadPolicyOrDefault(*policyPath)
	if err != nil {
		fatal(err)
	}
	kept := pol.Rules[:0]
	removed := 0
	for _, r := range pol.Rules {
		if r.Pattern == *pattern {
			removed++
			continue
		}
		kept = append(kept, r)
	}
	pol.Rules = kept
	if err := savePolicy(*policyPath, pol); err != nil {
		fatal(err)
	}
	fmt.Printf("removed %d rule(s) matching %q from %s\n", removed, *pattern, *policyPath)
}

func authorizeVerify(args []string) {
	fs := flag.NewFlagSet("authorize verify", flag.ContinueOnError)
	policyPath := fs.String("policy", defaultPolicyPath(), "policy file")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	pol, err := authz.LoadPolicy(*policyPath)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("policy %s is valid: mode=%s, %d rule(s)\n", *policyPath, modeName(pol.Mode), len(pol.Rules))
}

// ── CLI: audit ──────────────────────────────────────────────────────────────

func cmdAudit() {
	args := os.Args[2:]
	if len(args) == 0 {
		auditUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "show", "ls":
		auditShow(args[1:])
	case "verify":
		auditVerify(args[1:])
	case "help", "--help", "-h":
		auditUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown audit subcommand %q\n\n", args[0])
		auditUsage()
		os.Exit(2)
	}
}

func auditUsage() {
	fmt.Fprint(os.Stderr, `usage: stress-strike audit <show|verify> [flags]

  show    [--log PATH] [--limit N]   print recorded decisions
  verify  [--log PATH]               verify the hash chain (detect tampering)
`)
}

func auditShow(args []string) {
	fs := flag.NewFlagSet("audit show", flag.ContinueOnError)
	logPath := fs.String("log", defaultAuditPath(), "audit log file")
	limit := fs.Int("limit", 20, "show the last N entries (0 = all)")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	entries, err := authz.ReadAll(*logPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("no audit log at %s\n", *logPath)
			return
		}
		fatal(err)
	}
	if *limit > 0 && len(entries) > *limit {
		entries = entries[len(entries)-*limit:]
	}
	fmt.Printf("audit log: %s (%d record(s) shown)\n", *logPath, len(entries))
	for _, e := range entries {
		verdict := "ALLOW"
		if !e.Allowed {
			verdict = "DENY "
		}
		fmt.Printf("  #%-4d %s %s %-7s %-11s targets=%s\n",
			e.Seq, e.Time.Format(time.RFC3339), verdict, e.Action, e.Class, strings.Join(e.Targets, ","))
	}
}

func auditVerify(args []string) {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	logPath := fs.String("log", defaultAuditPath(), "audit log file")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	n, err := authz.Verify(*logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TAMPERED or corrupt: %v (verified %d record(s) before the break)\n", err, n)
		os.Exit(1)
	}
	fmt.Printf("OK: %d record(s), hash chain intact (%s)\n", n, *logPath)
}

// ── helpers ─────────────────────────────────────────────────────────────────

func savePolicy(path string, pol authz.Policy) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func modeName(m authz.Mode) string {
	if m == authz.ModeStrict {
		return "strict"
	}
	return "permissive"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
