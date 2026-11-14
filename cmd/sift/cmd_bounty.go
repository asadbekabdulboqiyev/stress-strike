package main

// cmd_bounty.go — the CLI face of the verifiable bug-bounty triage workflow.
//
// Four subcommands:
//
//	package  hash a report's artifacts into bounty-package.json
//	verify   re-hash the package, replay attestation evidence, check scope
//	triage   append one validated state transition to a triage log
//	status   replay a triage log and print its current state
//
// The workflow is staged and evidence-oriented. verify proves that the bytes
// are the packaged bytes and that the claimed target is in the packaged scope;
// it does not prove the finding is real, and the triage states (including
// "rewarded") are audit outcomes, not payments.
//
// The command is not yet wired into main.go's dispatch. It is kept in this file
// with the exact function name cmdBounty so wiring it later is a one-line
// change in a file this change does not own.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/bounty"
	"github.com/asadbekabdulboqiyev/sift/internal/version"
)

// cmdBounty dispatches `Sift bounty <subcommand>`.
func cmdBounty() {
	if len(os.Args) < 3 {
		bountyUsage()
		exitProcess(1)
		return
	}
	switch os.Args[2] {
	case "package":
		cmdBountyPackage()
	case "verify":
		cmdBountyVerify()
	case "triage":
		cmdBountyTriage()
	case "status":
		cmdBountyStatus()
	case "help", "-h", "--help":
		bountyUsage()
	default:
		fmt.Fprintf(os.Stderr, "error: unknown bounty subcommand %q\n\n", os.Args[2])
		bountyUsage()
		exitProcess(1)
	}
}

// cmdBountyPackage builds and writes a package manifest.
func cmdBountyPackage() {
	fs := flag.NewFlagSet("bounty package", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	bundlePath := fs.String("bundle", "", "path to the signed attestation bundle (optional)")
	samplesPath := fs.String("samples", "", "path to the sample sidecar (optional, requires --bundle)")
	reportPath := fs.String("report", "", "path to the vulnerability report (required)")
	scopePath := fs.String("scope", "", "path to the program scope file (required)")
	claimPath := fs.String("claim", "", "path to a typed claim.json (optional)")
	program := fs.String("program", "", "bug bounty program name (required)")
	programScope := fs.String("program-scope", "", "short human description of the program scope")
	policyURL := fs.String("policy-url", "", "program policy URL")
	outDir := fs.String("out", "", "directory to write bounty-package.json into (required)")

	if err := fs.Parse(os.Args[3:]); err != nil {
		bountyUsage()
		exitProcess(1)
		return
	}
	if fs.NArg() > 0 || strings.TrimSpace(*reportPath) == "" || strings.TrimSpace(*scopePath) == "" ||
		strings.TrimSpace(*program) == "" || strings.TrimSpace(*outDir) == "" {
		bountyUsage()
		exitProcess(1)
		return
	}

	m, err := bounty.BuildManifest(bounty.PackageOptions{
		BundlePath:       strings.TrimSpace(*bundlePath),
		SamplesPath:      strings.TrimSpace(*samplesPath),
		ReportPath:       strings.TrimSpace(*reportPath),
		ScopePath:        strings.TrimSpace(*scopePath),
		ClaimPath:        strings.TrimSpace(*claimPath),
		Program:          strings.TrimSpace(*program),
		ProgramScope:     strings.TrimSpace(*programScope),
		ProgramPolicyURL: strings.TrimSpace(*policyURL),
		ToolName:         "sift",
		ToolVersion:      version.Version,
	})
	if err != nil {
		fatal(err)
		return
	}

	path, err := bounty.WritePackage(m, strings.TrimSpace(*outDir))
	if err != nil {
		fatal(err)
		return
	}

	fmt.Printf("package:    %s\n", path)
	fmt.Printf("package id: %s\n", m.PackageID)
	fmt.Printf("digest:     %s\n", m.PackageDigest)
	fmt.Printf("artifacts:  %d\n", len(m.Artifacts))
	fmt.Fprintf(os.Stderr, "note: evidence integrity is not finding validity; human triage is still required\n")
}

// cmdBountyVerify verifies a package and exits with a status a pipeline can
// block on: 0 verified, 1 failed, 2 unverified/incomplete.
func cmdBountyVerify() {
	fs := flag.NewFlagSet("bounty verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	packagePath := fs.String("package", "", "path to bounty-package.json (required)")
	baseDir := fs.String("dir", "", "directory holding the package artifacts (required)")
	bundlePath := fs.String("bundle", "", "path to the attestation bundle to replay (optional)")
	samplesPath := fs.String("samples", "", "path to the sample sidecar to replay (optional)")
	publicKey := fs.String("key", "", "pin the coordinator public key (lowercase hex)")
	target := fs.String("target", "", "claimed target URL to check against the scope file")
	asJSON := fs.Bool("json", false, "emit a machine-readable report")
	maxSamples := fs.Int("max-samples", 0, "whole-file sidecar record limit (0 = built-in default)")
	skipCI := fs.Bool("skip-ci", false, "skip confidence-interval recomputation during attestation replay")

	if err := fs.Parse(os.Args[3:]); err != nil {
		bountyUsage()
		exitProcess(1)
		return
	}
	if fs.NArg() > 0 || strings.TrimSpace(*packagePath) == "" || strings.TrimSpace(*baseDir) == "" {
		bountyUsage()
		exitProcess(1)
		return
	}

	m, err := bounty.LoadPackage(strings.TrimSpace(*packagePath))
	if err != nil {
		fatal(err)
		return
	}

	report, err := bounty.VerifyPackage(m, strings.TrimSpace(*baseDir), bounty.VerifyOptions{
		BundlePath:      strings.TrimSpace(*bundlePath),
		SamplesPath:     strings.TrimSpace(*samplesPath),
		PublicKeyHex:    strings.TrimSpace(*publicKey),
		Target:          strings.TrimSpace(*target),
		MaxSamplesTotal: *maxSamples,
		SkipCICheck:     *skipCI,
	})
	if err != nil {
		fatal(err)
		return
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fatal(err)
			return
		}
	} else {
		printBountyReport(report, strings.TrimSpace(*packagePath))
	}

	switch report.Verdict {
	case bounty.VerdictVerified:
		return
	case bounty.VerdictFailed:
		exitProcess(1)
	default:
		exitProcess(2)
	}
}

// cmdBountyTriage appends one state transition after validating it.
func cmdBountyTriage() {
	fs := flag.NewFlagSet("bounty triage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	packagePath := fs.String("package", "", "path to bounty-package.json (required)")
	logPath := fs.String("log", "", "path to the triage JSONL log (required)")
	to := fs.String("to", "", "target state (required)")
	actor := fs.String("actor", "", "actor identity (required)")
	role := fs.String("role", "", "reporter, triager, program_owner or auditor (required)")
	reason := fs.String("reason", "", "reason for the transition (required)")

	if err := fs.Parse(os.Args[3:]); err != nil {
		bountyUsage()
		exitProcess(1)
		return
	}
	if fs.NArg() > 0 || strings.TrimSpace(*packagePath) == "" || strings.TrimSpace(*logPath) == "" ||
		strings.TrimSpace(*to) == "" || strings.TrimSpace(*actor) == "" ||
		strings.TrimSpace(*role) == "" || strings.TrimSpace(*reason) == "" {
		bountyUsage()
		exitProcess(1)
		return
	}

	m, err := bounty.LoadPackage(strings.TrimSpace(*packagePath))
	if err != nil {
		fatal(err)
		return
	}
	events, err := bounty.LoadEvents(strings.TrimSpace(*logPath))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fatal(err)
		return
	}
	current, err := bounty.CurrentState(events)
	if err != nil {
		fatal(err)
		return
	}

	event := bounty.Event{
		At:            time.Now().UTC().Format(time.RFC3339),
		Actor:         strings.TrimSpace(*actor),
		Role:          bounty.Role(strings.TrimSpace(*role)),
		From:          current,
		To:            bounty.State(strings.TrimSpace(*to)),
		Reason:        strings.TrimSpace(*reason),
		PackageDigest: m.PackageDigest,
	}
	if err := bounty.AppendEvent(strings.TrimSpace(*logPath), event); err != nil {
		fatal(err)
		return
	}

	fmt.Printf("state:  %s\n", event.To)
	fmt.Printf("from:   %s\n", stateDisplay(event.From))
	fmt.Printf("actor:  %s (%s)\n", event.Actor, event.Role)
	fmt.Printf("events: %d\n", len(events)+1)
	fmt.Printf("log:    %s\n", strings.TrimSpace(*logPath))
}

// cmdBountyStatus replays a triage log and prints the resulting state.
func cmdBountyStatus() {
	fs := flag.NewFlagSet("bounty status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	logPath := fs.String("log", "", "path to the triage JSONL log (required)")

	if err := fs.Parse(os.Args[3:]); err != nil {
		bountyUsage()
		exitProcess(1)
		return
	}
	if fs.NArg() > 0 || strings.TrimSpace(*logPath) == "" {
		bountyUsage()
		exitProcess(1)
		return
	}

	events, err := bounty.LoadEvents(strings.TrimSpace(*logPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("state:  %s\n", stateDisplay(bounty.StateNone))
			fmt.Printf("events: 0\n")
			return
		}
		fatal(err)
		return
	}
	current, err := bounty.CurrentState(events)
	if err != nil {
		fatal(err)
		return
	}

	fmt.Printf("state:  %s\n", stateDisplay(current))
	fmt.Printf("events: %d\n", len(events))
	if len(events) > 0 {
		last := events[len(events)-1]
		fmt.Printf("last:   %s by %s (%s)\n", last.At, last.Actor, last.Role)
		if last.Reason != "" {
			fmt.Printf("reason: %s\n", last.Reason)
		}
		if last.PackageDigest != "" {
			fmt.Printf("digest: %s\n", last.PackageDigest)
		}
	}
}

// printBountyReport renders a verification report for humans.
func printBountyReport(report bounty.VerificationReport, packagePath string) {
	fmt.Printf("verify %s\n", packagePath)
	if report.PackageID != "" {
		fmt.Printf("  package id: %s\n", report.PackageID)
	}
	if report.PackageDigest != "" {
		fmt.Printf("  digest:     %s\n", report.PackageDigest)
	}
	fmt.Println()
	for _, c := range report.Checks {
		detail := ""
		if c.Detail != "" && c.Status != bounty.StatusPass {
			detail = "  " + c.Detail
		}
		fmt.Printf("  %-24s %-4s%s\n", c.Name, strings.ToUpper(c.Status), detail)
	}
	if report.Attest != nil && report.Attest.Checked {
		fmt.Println()
		fmt.Printf("  attestation: %d checks, %d failed, %d workers, %d samples\n",
			report.Attest.ChecksRun, report.Attest.ChecksFailed,
			report.Attest.Workers, report.Attest.SamplesTotal)
		if report.Attest.BundleDigest != "" {
			fmt.Printf("  bundle:      %s\n", report.Attest.BundleDigest)
		}
	}
	fmt.Println()
	switch report.Verdict {
	case bounty.VerdictVerified:
		fmt.Println("VERIFIED — artifacts, manifest digest, evidence and scope all checked.")
	case bounty.VerdictUnverified:
		fmt.Println("UNVERIFIED — integrity checks passed, but at least one check was skipped.")
	default:
		fmt.Println("FAILED — at least one check did not pass.")
	}
	for _, reason := range report.Reasons {
		fmt.Printf("  - %s\n", reason)
	}
	if report.Verdict != bounty.VerdictVerified {
		fmt.Println("  note: evidence integrity is not finding validity; human triage is still required.")
	}
}

// stateDisplay renders StateNone clearly in CLI output.
func stateDisplay(s bounty.State) string {
	if s == bounty.StateNone {
		return "(none)"
	}
	return string(s)
}

// bountyUsage prints the command help.
func bountyUsage() {
	fmt.Fprint(os.Stderr, `Usage: Sift bounty <subcommand> [flags]

A staged, verifiable bug-bounty triage workflow. A package binds a report to
its evidence, its scope and its claim by digest; verification proves the bytes
are unchanged and (optionally) that the sealed measurements verify. It does not
prove the finding is valid, and the "rewarded" state is an audit outcome, not a
payment.

Subcommands:
  package   hash artifacts into a bounty-package.json
  verify    re-hash a package, replay evidence, check scope
  triage    append one validated state transition
  status    replay a triage log and print its state

package:
  Sift bounty package --bundle bundle.json --samples samples.jsonl \
      --report report.md --scope scope.txt --claim claim.json \
      --program "Acme Web" --out ./pkg

verify:
  Sift bounty verify --package ./pkg/bounty-package.json --dir ./pkg \
      --bundle bundle.json --samples samples.jsonl --key <hex> \
      --target https://api.example.com --json

  Exit status: 0 verified, 1 failed, 2 unverified/incomplete.

triage:
  Sift bounty triage --package ./pkg/bounty-package.json \
      --log triage.jsonl --to triaged --actor alice --role triager \
      --reason "confirmed on staging"

  States: submitted, triaged, needs_info, accepted, rejected, duplicate,
  rewarded. Roles: reporter, triager, program_owner, auditor (read-only).

status:
  Sift bounty status --log triage.jsonl
`)
}
