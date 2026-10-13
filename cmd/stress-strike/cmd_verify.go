package main

// cmd_verify.go — the VeriBench command surface: keygen and verify.
//
// These two commands are the whole user-facing protocol. keygen makes a
// coordinator's digital seal (an Ed25519 keypair in PEM); verify replays every
// check from scratch and exits 0 when the evidence is valid and 1 when it is
// not, so a CI pipeline can block on the result.
//
//	exit status
//	  0   the bundle is valid
//	  1   the bundle is invalid, or the command could not run (fail closed)

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
)

// cmdKeygen implements: stress-strike keygen --out <file>
//
// It writes an unencrypted Ed25519 keypair as PEM (PKCS#8 private key followed
// by the PKIX public key) with mode 0600 and prints the public key as lowercase
// hex, which is the value a bundle carries and an auditor can pin.
func cmdKeygen() {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "", "path to write the Ed25519 keypair (required)")
	force := fs.Bool("force", false, "overwrite an existing key file")

	if err := fs.Parse(os.Args[2:]); err != nil {
		keygenUsage()
		os.Exit(1)
	}
	if strings.TrimSpace(*out) == "" || fs.NArg() > 0 {
		keygenUsage()
		os.Exit(1)
	}
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			fatal(fmt.Errorf("keygen: %s already exists; use --force to overwrite it", *out))
		}
	}

	kp, err := attest.GenerateKeypair()
	if err != nil {
		fatal(err)
	}
	if err := attest.SaveKeypairPEM(kp, *out); err != nil {
		fatal(err)
	}

	fmt.Printf("public key: %s\n", attest.PublicKeyHex(kp.Public))
	fmt.Fprintf(os.Stderr, "keypair written to %s (private key mode 0600, unencrypted)\n", *out)
}

// cmdVerify implements: stress-strike verify --bundle <file> [--samples <file>]
//
// It loads the bundle, optionally loads the sidecar under explicit limits, and
// runs attest.Verify. Human output summarises the outcome; --json emits a
// machine-readable object. The process exits 0 only when every check passed.
func cmdVerify() {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bundlePath := fs.String("bundle", "", "path to bundle.json (required)")
	samplesPath := fs.String("samples", "", "path to the sidecar samples.jsonl (optional)")
	asJSON := fs.Bool("json", false, "emit a machine-readable JSON object")
	maxPerWorker := fs.Int("max-samples-per-worker", 0, "per-worker record limit (0 = built-in default)")
	maxTotal := fs.Int("max-samples", 0, "whole-file record limit (0 = built-in default)")
	proofLimit := fs.Int("proof-limit", 0, "SHA-256 budget for inclusion-proof verification (0 = built-in default)")
	skipCI := fs.Bool("skip-ci", false, "skip confidence-interval recomputation")
	expectKey := fs.String("expect-key", "", "pin the coordinator public key (lowercase hex) out of band")

	if err := fs.Parse(os.Args[2:]); err != nil {
		verifyUsage()
		os.Exit(1)
	}
	if strings.TrimSpace(*bundlePath) == "" || fs.NArg() > 0 {
		verifyUsage()
		os.Exit(1)
	}

	bundle, err := attest.LoadBundle(*bundlePath)
	if err != nil {
		fatal(err)
	}

	if key := strings.TrimSpace(*expectKey); key != "" {
		if !strings.EqualFold(key, bundle.Signature.Key) {
			fatal(fmt.Errorf("verify: bundle coordinator key %q does not match the pinned key %q", bundle.Signature.Key, key))
		}
	}

	var samples map[string][]attest.Record
	var loadStats attest.SampleLoadStats
	if p := strings.TrimSpace(*samplesPath); p != "" {
		opts := attest.DefaultSampleLoadOptions()
		if *maxPerWorker > 0 {
			opts.MaxSamplesPerWorker = *maxPerWorker
		}
		if *maxTotal > 0 {
			opts.MaxSamplesTotal = *maxTotal
		}
		samples, loadStats, err = attest.LoadSamples(p, opts)
		if err != nil {
			fatal(err)
		}
	}

	res := attest.VerifyWith(bundle, samples, attest.VerifyOptions{
		MaxSamplesPerWorker: *maxPerWorker,
		MaxSamplesTotal:     *maxTotal,
		ProofVerifyLimit:    *proofLimit,
		SkipCICheck:         *skipCI,
	})

	if *asJSON {
		if err := emitVerifyJSON(res, *bundlePath, *samplesPath, loadStats); err != nil {
			fatal(err)
		}
	} else {
		printVerifyHuman(res, *bundlePath, *samplesPath, loadStats)
	}

	if !res.Valid {
		os.Exit(1)
	}
}

// verifyJSONError mirrors attest.CheckError for the JSON output.
type verifyJSONError struct {
	Worker string `json:"worker,omitempty"`
	Check  string `json:"check"`
	Detail string `json:"detail"`
	Index  *int64 `json:"index,omitempty"`
}

// verifyJSON is the machine-readable verification report.
type verifyJSON struct {
	Valid          bool              `json:"valid"`
	Format         string            `json:"format"`
	Bundle         string            `json:"bundle"`
	BundleDigest   string            `json:"bundle_digest,omitempty"`
	Sidecar        string            `json:"sidecar,omitempty"`
	SamplesAbsent  bool              `json:"samples_absent"`
	Workers        int               `json:"workers"`
	WorkersOK      int               `json:"workers_ok"`
	SamplesTotal   int               `json:"samples_total"`
	ChecksRun      int               `json:"checks_run"`
	ChecksFailed   int               `json:"checks_failed"`
	ProofsVerified int               `json:"proofs_verified"`
	NonCanonical   int               `json:"non_canonical_lines,omitempty"`
	Errors         []verifyJSONError `json:"errors,omitempty"`
	Warnings       []string          `json:"warnings,omitempty"`
}

func emitVerifyJSON(res attest.VerifyResult, bundlePath, samplesPath string, stats attest.SampleLoadStats) error {
	out := verifyJSON{
		Valid:          res.Valid,
		Format:         res.Format,
		Bundle:         bundlePath,
		BundleDigest:   res.BundleDigest,
		Sidecar:        samplesPath,
		SamplesAbsent:  res.SamplesAbsent,
		Workers:        res.Summary.Workers,
		WorkersOK:      res.Summary.WorkersOK,
		SamplesTotal:   res.Summary.SamplesTotal,
		ChecksRun:      res.Summary.ChecksRun,
		ChecksFailed:   res.Summary.ChecksFailed,
		ProofsVerified: res.Summary.ProofsVerified,
		NonCanonical:   stats.NonCanonicalLines,
		Warnings:       res.Warnings,
	}
	for _, e := range res.Errors {
		out.Errors = append(out.Errors, verifyJSONError{Worker: e.Worker, Check: e.Check, Detail: e.Detail, Index: e.Index})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func printVerifyHuman(res attest.VerifyResult, bundlePath, samplesPath string, stats attest.SampleLoadStats) {
	fmt.Printf("verify %s\n", bundlePath)
	fmt.Printf("  format:        %s\n", res.Format)
	if res.BundleDigest != "" {
		fmt.Printf("  bundle digest: %s\n", res.BundleDigest)
	}
	if res.SamplesAbsent {
		fmt.Printf("  sidecar:       (absent: signature and internal consistency only)\n")
	} else {
		fmt.Printf("  sidecar:       %s (%d records, %d workers)\n", samplesPath, res.Summary.SamplesTotal, res.Summary.Workers)
		if stats.NonCanonicalLines > 0 {
			fmt.Printf("  note:          %d sidecar lines are not in canonical form\n", stats.NonCanonicalLines)
		}
	}
	fmt.Println()

	for _, w := range res.Workers {
		mark := "ok"
		if len(w.Errors) > 0 {
			mark = "FAIL"
		}
		n := w.Samples
		if n < 0 {
			n = 0
		}
		fmt.Printf("  worker %-14s %-4s  %6d records  %5d proofs\n", w.ID, mark, n, w.ProofsVerified)
	}
	if len(res.Workers) > 0 {
		fmt.Println()
	}

	if res.Valid {
		fmt.Printf("PASS — bundle is valid. %d checks passed across %d workers (%d records, %d inclusion proofs verified).\n",
			res.Summary.ChecksRun, res.Summary.Workers, res.Summary.SamplesTotal, res.Summary.ProofsVerified)
	} else {
		fmt.Printf("FAIL — bundle is not valid. %d of %d checks failed.\n", res.Summary.ChecksFailed, res.Summary.ChecksRun)
		for _, line := range res.ErrorLines() {
			fmt.Printf("  - %s\n", line)
		}
	}
	for _, w := range res.Warnings {
		fmt.Printf("  warning: %s\n", w)
	}
}

func keygenUsage() {
	fmt.Fprint(os.Stderr, `Usage: stress-strike keygen --out <file>

Creates an Ed25519 coordinator keypair for VeriBench, written as PEM
(PKCS#8 private key + PKIX public key, mode 0600), and prints the public
key as lowercase hex.

Flags:
  --out string    path to write the keypair (required)
  --force         overwrite an existing key file

Example:
  stress-strike keygen --out /tmp/veribench.key
`)
}

func verifyUsage() {
	fmt.Fprint(os.Stderr, `Usage: stress-strike verify --bundle <bundle.json> [--samples <samples.jsonl>]

Verifies a VeriBench (vpmp/v1) evidence pack. It replays every check from
scratch: the coordinator signature, each worker's commit signature, the
Merkle root recomputed from the raw records, the aggregates, the run-wide
percentiles and the confidence interval.

Exit status: 0 if the bundle is valid, 1 otherwise.

Flags:
  --bundle string                  path to bundle.json (required)
  --samples string                 path to the sidecar samples.jsonl (optional)
  --json                           emit a machine-readable JSON report
  --expect-key string              pin the coordinator public key (hex) out of band
  --max-samples-per-worker int     per-worker record limit (0 = default)
  --max-samples int                whole-file record limit (0 = default)
  --proof-limit int                SHA-256 budget for proof verification
  --skip-ci                        skip confidence-interval recomputation

Examples:
  stress-strike verify --bundle bundle.json --samples bundle.samples.jsonl
  stress-strike verify --bundle bundle.json --json
`)
}
