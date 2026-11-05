package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/scanner"
)

// cmd_jwt.go implements `stress-strike jwt`: the CLI face of the dashboard's
// POST /api/jwt/scan. It is a pure offline analysis — the token is decoded and
// inspected locally, nothing is sent anywhere — so it registers NO
// authorization flag and needs no probe gate: analyze() has no network path.
//
// The token is read from --token, from --file, or from stdin (so a token can be
// piped in without landing in the shell history or the process table). Unlike
// the dashboard, the result NEVER echoes the token back: a JWT is a bearer
// credential, and the company rule is that user tokens are never logged. The
// report therefore carries only the decoded header/payload and the findings.
func cmdJWT() {
	var (
		tokenFlag string
		fileFlag  string
	)
	sf := &scanFlags{}

	fs := flag.NewFlagSet("jwt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&tokenFlag, "token", "", "JWT to analyze (or use --file / stdin)")
	fs.StringVar(&fileFlag, "file", "", "read the JWT from this file (or use --token / stdin)")
	addScanOutputFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printJWTHelp(fs) }, cliux.Options{
		Command: "jwt",
		FlagSet: fs,
		Examples: []string{
			"stress-strike jwt --token eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
		},
	})

	token, err := resolveJWTInput(tokenFlag, fileFlag)
	if err != nil {
		fatal(err)
	}

	result := scanner.AnalyzeJWT(token)
	report := jwtReport{
		Valid:         result.Valid,
		AlgoConfusion: result.AlgoConfusion,
		Header:        result.Header,
		Payload:       result.Payload,
		Issues:        result.Issues,
	}

	if err := emitScanJSON(report, sf); err != nil {
		fatal(err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Println("jwt analysis")
	fmt.Printf("  valid:          %v\n", report.Valid)
	fmt.Printf("  algo confusion: %v\n", report.AlgoConfusion)
	if report.Header != nil {
		fmt.Printf("  header:         %s\n", compactJSON(report.Header))
	}
	if report.Payload != nil {
		fmt.Printf("  payload:        %s\n", compactJSON(report.Payload))
	}
	if len(report.Issues) == 0 {
		fmt.Println("  issues:         none")
		return
	}
	fmt.Printf("  issues:         %d\n", len(report.Issues))
	for _, issue := range report.Issues {
		fmt.Printf("    - %s\n", issue)
	}
}

// jwtReport is the CLI's token-redacted view of a scanner.JWTResult. It carries
// everything the human needs but deliberately omits the raw token, which
// scanner.JWTResult echoes back in its Token field.
type jwtReport struct {
	Valid         bool           `json:"valid"`
	AlgoConfusion bool           `json:"algo_confusion,omitempty"`
	Header        map[string]any `json:"header,omitempty"`
	Payload       map[string]any `json:"payload,omitempty"`
	Issues        []string       `json:"issues,omitempty"`
}

// resolveJWTInput picks the token source: --token wins, then --file, then stdin
// when it is not an interactive terminal. It refuses to hang waiting for a TTY
// the operator did not mean to type into.
func resolveJWTInput(tokenFlag, fileFlag string) (string, error) {
	if tok := strings.TrimSpace(tokenFlag); tok != "" {
		return tok, nil
	}
	if path := strings.TrimSpace(fileFlag); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		tok := strings.TrimSpace(string(data))
		if tok == "" {
			return "", fmt.Errorf("file %s is empty", path)
		}
		return tok, nil
	}
	if isInteractiveTerminal() {
		return "", fmt.Errorf("no token provided\n\nPass --token <jwt>, --file <path>, or pipe a token on stdin.\n\nExample: stress-strike jwt --token eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", fmt.Errorf("no token provided on stdin")
	}
	return tok, nil
}

// printJWTHelp renders `stress-strike jwt --help`.
func printJWTHelp(fs *flag.FlagSet) {
	w := os.Stderr
	fmt.Fprintf(w, "\n stress-strike jwt — offline JWT weakness analyzer\n\n")
	fmt.Fprintf(w, " USAGE\n")
	fmt.Fprintf(w, "   stress-strike jwt --token <jwt>\n")
	fmt.Fprintf(w, "   cat token.txt | stress-strike jwt\n\n")
	fmt.Fprintf(w, " Decodes the header and payload locally and reports algorithm confusion\n")
	fmt.Fprintf(w, " (alg=none), missing/expired claims, and injection headers (kid/jku/x5u).\n")
	fmt.Fprintf(w, " Offline only — nothing is sent, so no authorization gate applies. The\n")
	fmt.Fprintf(w, " token itself is never echoed back in the output or the JSON report.\n\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " FLAGS\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " EXAMPLES\n")
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Analyze a token directly",
		"stress-strike jwt --token eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
		"",
		"# Read from a file, or pipe it (keeps it out of shell history)",
		"stress-strike jwt --file token.txt",
		"cat token.txt | stress-strike jwt",
		"",
		"# Machine-readable output",
		"stress-strike jwt --token <jwt> --json",
	} {
		fmt.Fprintf(w, "\n   %s\n", e)
	}
	fmt.Fprintf(w, "\n")
}
