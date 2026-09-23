// Package cliux provides shared, friendly CLI ergonomics for every
// stress-strike binary: human-readable flag errors with "did you mean"
// suggestions, consistent two-dash flag listings, and a uniform boxed help
// layout. It never changes flag names or exit-code conventions:
//
//   - flag/usage errors exit 2 (the same code Go's flag package uses)
//   - --help / -h exit 0
//
// Usage functions calling into this package must write to the target writer
// (usually os.Stderr) directly — flag.Parse output is discarded so raw Go
// flag noise never reaches the user.
package cliux

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

// Options describes how to render a friendly flag parse error.
type Options struct {
	// Command is the subcommand name, e.g. "run" or "scan". Used to build
	// the "Run 'stress-strike <command> --help' ..." hint. When empty the
	// hint falls back to the program basename.
	Command string
	// FlagSet holds the registered flags used for "did you mean" and type
	// hints. May be nil (message-only rendering).
	FlagSet *flag.FlagSet
	// Err is the error returned by fs.Parse.
	Err error
	// Examples are example invocations; the first is shown on error.
	Examples []string
}

// Parse wraps fs.Parse with friendly CLI UX. It never returns when parsing
// is interrupted:
//
//   - on -h/--help it calls onHelp and exits 0;
//   - on a parse error it renders a friendly message and exits 2.
//
// Raw Go flag output is suppressed, so onHelp must write directly to the
// target writer and use PrintFlagList for flag listings instead of
// fs.PrintDefaults.
func Parse(fs *flag.FlagSet, args []string, onHelp func(), o Options) {
	fs.SetOutput(io.Discard)
	helpSaved := fs.Usage
	fs.Usage = func() {} // suppress automatic usage dumps on parse errors
	err := fs.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			onHelp()
			os.Exit(0)
		}
		o.FlagSet = fs
		o.Err = err
		os.Exit(HandleFlagError(os.Stderr, o))
	}
	// Success: restore the original usage/output so later flag.Usage() calls
	// (e.g. "required flag missing" checks) still render normally.
	fs.Usage = helpSaved
	fs.SetOutput(os.Stderr)
}

// HandleFlagError prints a friendly, actionable message for a flag parse
// error and returns the process exit code (2, matching Go's usage-error
// convention and the SLA-gate exit code).
func HandleFlagError(w io.Writer, o Options) int {
	if o.Err == nil {
		return 2
	}
	msg := o.Err.Error()
	names := FlagNames(o.FlagSet)

	switch {
	case strings.HasPrefix(msg, "flag needs an argument:"):
		name := trimFlagName(strings.TrimPrefix(msg, "flag needs an argument:"))
		errorf(w, "Flag --%s requires a value.", name)
		if t := typeHint(o.FlagSet, name); t != "" {
			fmt.Fprintf(w, "          (expects %s)\n", t)
		}
	case strings.HasPrefix(msg, "flag provided but not defined:"):
		name := trimFlagName(strings.TrimPrefix(msg, "flag provided but not defined:"))
		errorf(w, "Unknown flag --%s.", name)
		if suggs := Suggestions(name, names, 3); len(suggs) > 0 {
			fmt.Fprintf(w, "Did you mean --%s?\n", strings.Join(suggs, " or --"))
		}
	case strings.HasPrefix(msg, "invalid value"):
		name, val := parseInvalidValue(msg)
		errorf(w, "Invalid value %s for flag --%s.", displayValue(val), name)
		if t := typeHint(o.FlagSet, name); t != "" {
			fmt.Fprintf(w, "          (expects %s)\n", t)
		}
	case strings.HasPrefix(msg, "bad flag syntax"):
		errorf(w, "%s.", strings.TrimSpace(msg))
	default:
		errorf(w, "%s", strings.TrimSpace(msg))
	}

	if len(o.Examples) > 0 {
		fmt.Fprintf(w, "\nExample:\n  %s\n", o.Examples[0])
	}
	fmt.Fprintf(w, "\nRun '%s --help' to see all flags and examples.\n", helpCommand(o))
	return 2
}

func helpCommand(o Options) string {
	if o.Command != "" {
		return "stress-strike " + o.Command
	}
	if len(os.Args) > 0 && os.Args[0] != "" {
		return os.Args[0]
	}
	return "stress-strike"
}

func errorf(w io.Writer, format string, a ...any) {
	if IsColorable(w) {
		fmt.Fprintf(w, "\x1b[1;31mError:\x1b[0m "+format+"\n", a...)
	} else {
		fmt.Fprintf(w, "Error: "+format+"\n", a...)
	}
}

// ── Flag name / value extraction from Go flag errors ──────────────────────

func trimFlagName(s string) string {
	return strings.TrimLeft(strings.TrimSpace(s), "-")
}

// parseInvalidValue parses: invalid value "abc" for flag -users: parse error
func parseInvalidValue(msg string) (name, val string) {
	rest := strings.TrimPrefix(msg, "invalid value")
	rest = strings.TrimSpace(rest)
	if idx := strings.Index(rest, `"`); idx >= 0 {
		rest = rest[idx+1:]
		if end := strings.Index(rest, `"`); end >= 0 {
			val = rest[:end]
			rest = rest[end+1:]
		}
	}
	if i := strings.Index(rest, "for flag -"); i >= 0 {
		rest = rest[i+len("for flag -"):]
		if j := strings.Index(rest, ":"); j >= 0 {
			name = strings.TrimSpace(rest[:j])
		}
	}
	return name, val
}

func displayValue(v string) string {
	if v == "" {
		return `""`
	}
	return fmt.Sprintf("%q", v)
}

// typeHint maps a flag's Go type to a human phrasing.
func typeHint(fs *flag.FlagSet, name string) string {
	if fs == nil {
		return ""
	}
	f := fs.Lookup(name)
	if f == nil {
		return ""
	}
	switch flagTypeName(f) {
	case "string":
		return "a string"
	case "int", "uint":
		return "an integer"
	case "float":
		return "a number"
	case "bool":
		return "true or false"
	case "duration":
		return "a duration, e.g. 30s or 5m"
	default:
		return ""
	}
}

// ── "Did you mean" suggestions ────────────────────────────────────────────

// Levenshtein returns the edit distance between a and b.
func Levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	la, lb := len(ar), len(br)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[lb]
}

// Suggestions returns up to max candidates closest to input, ordered by
// edit distance then name. A candidate qualifies when its edit distance is
// <= 2 or it is a prefix match (input length >= 2).
func Suggestions(input string, candidates []string, max int) []string {
	if input == "" || max <= 0 {
		return nil
	}
	type scored struct {
		cand string
		d    int
	}
	seen := map[string]bool{}
	var out []scored
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		d := Levenshtein(input, c)
		if d <= 2 || (len(input) >= 2 && strings.HasPrefix(c, input)) {
			out = append(out, scored{c, d})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].d != out[j].d {
			return out[i].d < out[j].d
		}
		return out[i].cand < out[j].cand
	})
	if len(out) > max {
		out = out[:max]
	}
	res := make([]string, 0, len(out))
	for _, s := range out {
		res = append(res, s.cand)
	}
	return res
}

// FlagNames returns the registered flag names of fs in lexicographic order.
func FlagNames(fs *flag.FlagSet) []string {
	if fs == nil {
		return nil
	}
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	return names
}

// ── Pretty two-dash flag listing ──────────────────────────────────────────

type boolFlag interface{ IsBoolFlag() bool }

func isBoolFlag(f *flag.Flag) bool {
	if bf, ok := f.Value.(boolFlag); ok {
		return bf.IsBoolFlag()
	}
	return false
}

// flagTypeName mirrors the flag package's inferred type used in usage text.
func flagTypeName(f *flag.Flag) string {
	t := reflect.TypeOf(f.Value)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil {
		return "value"
	}
	switch t.Kind() {
	case reflect.Bool:
		return "bool"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if t.PkgPath() == "time" && t.Name() == "Duration" {
			return "duration"
		}
		return "int"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "uint"
	case reflect.Float32, reflect.Float64:
		return "float"
	case reflect.String:
		return "string"
	case reflect.Map, reflect.Slice, reflect.Struct, reflect.Array:
		return "value"
	default:
		return "value"
	}
}

// isZeroValue reports whether the default value is the type's zero value,
// mirroring the flag package's logic (so "(default X)" is only shown when
// meaningful).
func isZeroValue(f *flag.Flag, value string) bool {
	typ := reflect.TypeOf(f.Value)
	var z reflect.Value
	if typ.Kind() == reflect.Pointer {
		z = reflect.New(typ.Elem())
	} else {
		z = reflect.Zero(typ)
	}
	return value == z.Interface().(flag.Value).String()
}

// PrintFlagList writes an aligned, two-dash flag listing to w. Flags are
// visited in lexicographic order, matching flag.PrintDefaults.
func PrintFlagList(w io.Writer, fs *flag.FlagSet) {
	type entry struct{ left, desc string }
	var entries []entry
	maxLeft := 0
	fs.VisitAll(func(f *flag.Flag) {
		left := "--" + f.Name
		if !isBoolFlag(f) {
			left += " " + flagTypeName(f)
		}
		desc := f.Usage
		if !isZeroValue(f, f.DefValue) {
			if flagTypeName(f) == "string" {
				desc += fmt.Sprintf(" (default %q)", f.DefValue)
			} else {
				desc += fmt.Sprintf(" (default %v)", f.DefValue)
			}
		}
		entries = append(entries, entry{left, desc})
		if len(left) > maxLeft {
			maxLeft = len(left)
		}
	})
	for _, e := range entries {
		fmt.Fprintf(w, "  %-*s  %s\n", maxLeft, e.left, e.desc)
	}
}

// ── Boxed help (master / worker and friends) ──────────────────────────────

// BoxHelp renders help in the same sectioned style as the top-level
// `stress-strike --help`, with USAGE, FLAGS and EXAMPLES sections.
func BoxHelp(w io.Writer, title string, usage []string, examples []string, fs *flag.FlagSet) {
	fmt.Fprintf(w, "\n %s\n\n", title)
	fmt.Fprintf(w, " USAGE\n")
	for _, u := range usage {
		fmt.Fprintf(w, "   %s\n", u)
	}
	sep(w)
	fmt.Fprintf(w, " FLAGS\n")
	sep(w)
	PrintFlagList(w, fs)
	if len(examples) > 0 {
		fmt.Fprintf(w, "\n")
		sep(w)
		fmt.Fprintf(w, " EXAMPLES\n")
		sep(w)
		for _, e := range examples {
			fmt.Fprintf(w, "\n   %s\n", e)
		}
	}
	fmt.Fprintf(w, "\n")
}

func sep(w io.Writer) {
	fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
}

// ── TTY / color detection ─────────────────────────────────────────────────

// IsColorable reports whether w is a TTY and colors are not disabled via
// NO_COLOR.
func IsColorable(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
