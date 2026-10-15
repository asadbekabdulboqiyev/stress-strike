package main

// cmd_verify_test.go — black-box end-to-end tests for the VeriBench command
// surface (keygen and verify).
//
// keygen and verify call os.Exit, so they cannot be driven in-process without
// killing the test binary. Instead these tests build the real executable once
// and run it as a subprocess: only the shipped CLI and the exported attest /
// honesty APIs take part, exactly what a user and a CI pipeline do.
//
// The pack the tests verify is produced through the same public API a real
// producer would use (BuildCommit, AggregateRecords, Bundle.Sign), so a pack
// that verifies proves the producer and the verifier agree end to end.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/honesty"
)

// -----------------------------------------------------------------------------
// Building and driving the real CLI
// -----------------------------------------------------------------------------

var (
	cliBuildOnce sync.Once
	cliBin       string
	cliDir       string
	cliBuildErr  error
)

// TestMain builds the CLI once and removes the temporary build directory after
// the whole package's tests have run. Existing tests are unaffected: their
// bodies still run under m.Run().
func TestMain(m *testing.M) {
	buildCLI()
	code := m.Run()
	if cliDir != "" {
		_ = os.RemoveAll(cliDir)
	}
	os.Exit(code)
}

// buildCLI compiles the package's main binary into a temporary directory. It is
// idempotent so every test can call it without paying the build cost twice.
func buildCLI() {
	cliBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "stress-strike-cli")
		if err != nil {
			cliBuildErr = err
			return
		}
		cliDir = dir
		bin := filepath.Join(dir, "stress-strike")
		if runtime.GOOS == "windows" {
			// `go build -o` appends the extension on Windows, so the artifact
			// lands at "stress-strike.exe" while cliBin would point at the
			// extensionless path — exec then reports "file not found in %PATH%"
			// and every black-box CLI test fails, all from this one line.
			bin += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", bin, ".")
		if out, err := cmd.CombinedOutput(); err != nil {
			cliBuildErr = fmt.Errorf("go build: %w\n%s", err, out)
			return
		}
		cliBin = bin
	})
}

// cliResult captures one CLI invocation.
type cliResult struct {
	stdout string
	stderr string
	code   int
}

// runCLI executes the built binary with the given arguments and returns its
// streams and exit status. A failure to start the process (as opposed to a
// non-zero exit) fails the test: it means the harness, not the CLI, broke.
func runCLI(t *testing.T, args ...string) cliResult {
	t.Helper()
	if cliBuildErr != nil {
		t.Fatalf("CLI build failed: %v", cliBuildErr)
	}
	if cliBin == "" {
		t.Fatal("CLI binary was not built")
	}
	cmd := exec.Command(cliBin, args...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return cliResult{stdout: out.String(), stderr: errb.String(), code: code}
}

// -----------------------------------------------------------------------------
// Pack producer (the honest side), built only from exported API
// -----------------------------------------------------------------------------

// vbRecords returns n already-ordered records for one worker.
func vbRecords(id string, n int) []attest.Record {
	recs := make([]attest.Record, n)
	for i := 0; i < n; i++ {
		recs[i] = attest.Record{
			Seq:       uint64(i + 1),
			Worker:    id,
			StartNS:   int64(i) * 100_000_000, // 100 ms apart
			LatencyNS: 1_000_000 + int64(i)*10_000,
			Status:    200,
			Bytes:     1024 + int64(i),
		}
	}
	return recs
}

// vbPlannedRPS is the paced target for the 5-records-over-10s pack the tests
// produce: 5 requests / 10 s = 0.5 rps, spelled as an exact canonical decimal.
const vbPlannedRPS = attest.Decimal("0.500")

// vbMillis converts a Decimal to scaled milli units or fails the test.
func vbMillis(t *testing.T, d attest.Decimal) int64 {
	t.Helper()
	m, err := d.Milli()
	if err != nil {
		t.Fatalf("Decimal(%q).Milli(): %v", d, err)
	}
	return m
}

// vbBuildBundle produces a fully valid, signed single-worker bundle from recs,
// using the worker key for the commit and the coordinator key for the seal.
func vbBuildBundle(t *testing.T, coord, worker *attest.Keypair, id string, recs []attest.Record) attest.Bundle {
	t.Helper()
	run := attest.Run{
		Target:     "https://example.test/api",
		Profile:    "constant-rps",
		DurationNS: 10_000_000_000,
		PlannedRPS: vbPlannedRPS,
	}
	rpsMilli := vbMillis(t, run.PlannedRPS)

	ordered := attest.SortRecords(recs)
	commit, err := attest.BuildCommit(worker, recs)
	if err != nil {
		t.Fatalf("BuildCommit: %v", err)
	}
	stats, err := attest.AggregateRecords(ordered, 0, false, 0)
	if err != nil {
		t.Fatalf("AggregateRecords: %v", err)
	}

	var count, sum uint64
	values := make([]int64, 0, len(ordered))
	for _, r := range ordered {
		count++
		sum += uint64(r.LatencyNS)
		values = append(values, r.LatencyNS)
	}

	achievedMilli, err := honesty.AchievedRPSMilli(count, run.DurationNS)
	if err != nil {
		t.Fatalf("AchievedRPSMilli: %v", err)
	}
	rps, err := attest.DecimalFromMilli(achievedMilli)
	if err != nil {
		t.Fatalf("DecimalFromMilli: %v", err)
	}
	dropped, err := honesty.DroppedSamples(rpsMilli, run.DurationNS, count)
	if err != nil {
		t.Fatalf("DroppedSamples: %v", err)
	}
	sorted := honesty.SortValues(values)

	b := attest.Bundle{
		Format:    attest.FormatID,
		CreatedAt: "2026-10-13T18:00:00Z",
		Tool:      attest.Tool{Name: "stress-strike", Version: "test"},
		Run:       run,
		Workers: []attest.WorkerBundle{{
			ID:        id,
			PublicKey: attest.PublicKeyHex(worker.Public),
			Commit:    commit,
			Aggregate: attest.WorkerAgg{
				Count:        stats.Count,
				SumLatencyNS: stats.SumLatencyNS,
				MinNS:        stats.MinNS,
				MaxNS:        stats.MaxNS,
				Hist:         stats.Hist,
			},
		}},
		Aggregate: attest.Aggregate{
			Count:        count,
			SumLatencyNS: sum,
			P50NS:        honesty.Percentile(sorted, honesty.PPM50),
			P95NS:        honesty.Percentile(sorted, honesty.PPM95),
			P99NS:        honesty.Percentile(sorted, honesty.PPM99),
			RPS:          rps,
		},
		Integrity: attest.Integrity{
			ScheduleAccuracyPPM: honesty.ScheduleAccuracyPPM(rpsMilli, achievedMilli),
			DroppedSamples:      dropped,
			AchievedRPS:         rps,
			PlannedRPS:          run.PlannedRPS,
		},
	}
	if err := b.Sign(coord); err != nil {
		t.Fatalf("Bundle.Sign: %v", err)
	}
	return b
}

// vbWritePack writes a valid bundle and its sidecar into dir and returns the
// two paths plus the records in canonical order.
func vbWritePack(t *testing.T, coord, worker *attest.Keypair, id string, recs []attest.Record) (bundlePath, samplesPath string, ordered []attest.Record) {
	t.Helper()
	dir := t.TempDir()
	b := vbBuildBundle(t, coord, worker, id, recs)
	ordered = attest.SortRecords(recs)

	bundlePath = filepath.Join(dir, "bundle.json")
	if err := attest.SaveBundle(b, bundlePath); err != nil {
		t.Fatalf("SaveBundle: %v", err)
	}
	samplesPath = filepath.Join(dir, "bundle.samples.jsonl")
	f, err := os.Create(samplesPath)
	if err != nil {
		t.Fatalf("create sidecar: %v", err)
	}
	if err := attest.WriteSamples(f, ordered); err != nil {
		_ = f.Close()
		t.Fatalf("WriteSamples: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close sidecar: %v", err)
	}
	return bundlePath, samplesPath, ordered
}

// vbFreshKeys returns a coordinator and a worker keypair.
func vbFreshKeys(t *testing.T) (*attest.Keypair, *attest.Keypair) {
	t.Helper()
	coord, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair(coord): %v", err)
	}
	worker, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair(worker): %v", err)
	}
	return coord, worker
}

// -----------------------------------------------------------------------------
// keygen
// -----------------------------------------------------------------------------

var publicKeyLine = regexp.MustCompile(`^public key: ([0-9a-f]{64})$`)

// TestCLIKeygenRoundTrip checks that keygen writes a usable keypair, prints the
// matching public key, refuses to clobber without --force, and that the key the
// file contains is the key it advertised.
func TestCLIKeygenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "coord.key")

	res := runCLI(t, "keygen", "--out", keyPath)
	if res.code != 0 {
		t.Fatalf("keygen exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	line := strings.TrimSpace(res.stdout)
	m := publicKeyLine.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("keygen stdout = %q, want a single 'public key: <64 hex>' line", line)
	}
	advertised := m[1]

	kp, err := attest.LoadKeypairPEM(keyPath)
	if err != nil {
		t.Fatalf("LoadKeypairPEM(%s): %v", keyPath, err)
	}
	if got := attest.PublicKeyHex(kp.Public); got != advertised {
		t.Fatalf("key on disk is %s, but keygen printed %s", got, advertised)
	}

	// The 0600 guarantee is a POSIX one. Windows has no mode bits — Go
	// synthesises 0666 for any writable file — so asserting the octal value
	// there would test an unimplemented property and fail for the wrong
	// reason. On Windows the key's protection comes from the per-user profile
	// directory's ACL, not from this number.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("stat key file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("key file mode = %o, want 0600", perm)
		}
	}

	// A second keygen without --force must fail closed rather than silently
	// replacing a coordinator identity.
	if res := runCLI(t, "keygen", "--out", keyPath); res.code == 0 {
		t.Fatalf("keygen overwrote an existing key without --force (exit 0)")
	}

	// With --force it succeeds and the on-disk key changes.
	res = runCLI(t, "keygen", "--out", keyPath, "--force")
	if res.code != 0 {
		t.Fatalf("keygen --force exit = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	kp2, err := attest.LoadKeypairPEM(keyPath)
	if err != nil {
		t.Fatalf("LoadKeypairPEM after --force: %v", err)
	}
	if attest.PublicKeyHex(kp2.Public) == advertised {
		t.Fatalf("--force did not replace the key")
	}
}

// TestCLIKeygenRequiresOut checks the usage-error path.
func TestCLIKeygenRequiresOut(t *testing.T) {
	res := runCLI(t, "keygen")
	if res.code != 1 {
		t.Fatalf("keygen with no --out exit = %d, want 1", res.code)
	}
	if !strings.Contains(res.stderr, "Usage: stress-strike keygen") {
		t.Fatalf("usage missing from stderr:\n%s", res.stderr)
	}
}

// -----------------------------------------------------------------------------
// verify — the valid path
// -----------------------------------------------------------------------------

// TestCLIKeygenVerifyEndToEnd drives the whole advertised workflow: generate a
// coordinator key with keygen, produce a pack signed by that exact key, then
// verify it with the shipped binary and expect exit 0.
func TestCLIKeygenVerifyEndToEnd(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "coord.key")

	if res := runCLI(t, "keygen", "--out", keyPath); res.code != 0 {
		t.Fatalf("keygen exit = %d\nstderr:\n%s", res.code, res.stderr)
	}
	coord, err := attest.LoadKeypairPEM(keyPath)
	if err != nil {
		t.Fatalf("LoadKeypairPEM: %v", err)
	}
	worker, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair(worker): %v", err)
	}

	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath)
	if res.code != 0 {
		t.Fatalf("verify exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "PASS") {
		t.Fatalf("verify stdout does not report PASS:\n%s", res.stdout)
	}

	// The same pack with only the bundle (no sidecar) must also pass: the
	// signature and internal consistency are checkable without the receipts.
	res = runCLI(t, "verify", "--bundle", bundlePath)
	if res.code != 0 {
		t.Fatalf("verify (no sidecar) exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}

	// An out-of-band pin of the correct coordinator key must pass, and a wrong
	// pin must fail closed.
	res = runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath, "--expect-key", attest.PublicKeyHex(coord.Public))
	if res.code != 0 {
		t.Fatalf("verify with correct --expect-key exit = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	res = runCLI(t, "verify", "--bundle", bundlePath, "--expect-key", strings.Repeat("0", 64))
	if res.code != 1 {
		t.Fatalf("verify with wrong --expect-key exit = %d, want 1", res.code)
	}
}

// TestCLIVerifyJSONOutput checks the machine-readable report a CI job would
// parse: a valid pack must report valid=true with no failed checks.
func TestCLIVerifyJSONOutput(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath, "--json")
	if res.code != 0 {
		t.Fatalf("verify --json exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}

	var got verifyJSON
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\n%s", err, res.stdout)
	}
	if !got.Valid {
		t.Fatalf("report.valid = false, want true; errors=%+v", got.Errors)
	}
	if got.Format != "vpmp/v1" {
		t.Fatalf("report.format = %q, want vpmp/v1", got.Format)
	}
	if got.Workers != 1 || got.WorkersOK != 1 {
		t.Fatalf("report workers = %d ok = %d, want 1/1", got.Workers, got.WorkersOK)
	}
	if got.SamplesTotal != 5 {
		t.Fatalf("report.samples_total = %d, want 5", got.SamplesTotal)
	}
	if got.ChecksFailed != 0 || len(got.Errors) != 0 {
		t.Fatalf("report shows failures: checks_failed=%d errors=%+v", got.ChecksFailed, got.Errors)
	}
	if got.BundleDigest == "" {
		t.Fatalf("report.bundle_digest is empty")
	}
}

// -----------------------------------------------------------------------------
// verify — the fail-closed paths
// -----------------------------------------------------------------------------

// TestCLIVerifyTamperedSampleFails flips one digit of one record in the sidecar
// and requires the CLI to reject the pack with exit 1, naming the cause.
func TestCLIVerifyTamperedSampleFails(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	raw, err := os.ReadFile(samplesPath)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	// Record 0 has latency_ns 1000000 and no other record shares that value, so
	// this replacement touches exactly one byte of one canonical line.
	tampered := strings.Replace(string(raw), `"latency_ns":1000000`, `"latency_ns":1000001`, 1)
	if tampered == string(raw) {
		t.Fatalf("tamper did not change the sidecar")
	}
	if err := os.WriteFile(samplesPath, []byte(tampered), 0o644); err != nil {
		t.Fatalf("write tampered sidecar: %v", err)
	}

	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath, "--json")
	if res.code != 1 {
		t.Fatalf("verify tampered exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}

	var got verifyJSON
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("tampered --json output is not valid JSON: %v\n%s", err, res.stdout)
	}
	if got.Valid {
		t.Fatalf("tampered pack reported valid")
	}
	if len(got.Errors) == 0 {
		t.Fatalf("tampered pack reported no errors")
	}
}

// TestCLIVerifyBrokenBundleSignatureFails corrupts one hex character of the
// coordinator seal and requires exit 1.
func TestCLIVerifyBrokenBundleSignatureFails(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	b, err := attest.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	flipped := flipFirstHex(b.Signature.Sig)
	if flipped == b.Signature.Sig {
		t.Fatalf("failed to flip a signature character")
	}
	b.Signature.Sig = flipped
	if err := attest.SaveBundle(b, bundlePath); err != nil {
		t.Fatalf("SaveBundle (tampered): %v", err)
	}

	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath)
	if res.code != 1 {
		t.Fatalf("verify broken-signature exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "FAIL") {
		t.Fatalf("broken signature did not report FAIL:\n%s", res.stdout)
	}
}

// TestCLIVerifyMissingBundleIsUsageError checks the argument validation path.
func TestCLIVerifyMissingBundleIsUsageError(t *testing.T) {
	res := runCLI(t, "verify")
	if res.code != 1 {
		t.Fatalf("verify with no --bundle exit = %d, want 1", res.code)
	}
	if !strings.Contains(res.stderr, "Usage: stress-strike verify") {
		t.Fatalf("usage missing from stderr:\n%s", res.stderr)
	}
}

// TestCLIVerifyMalformedBundleNoPanic truncates the bundle JSON and requires a
// clean exit 1 — never a panic (which would show as exit 2).
func TestCLIVerifyMalformedBundleNoPanic(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"format":"vpmp/v1","tool":`), 0o644); err != nil {
		t.Fatalf("write truncated bundle: %v", err)
	}

	res := runCLI(t, "verify", "--bundle", bundlePath)
	if res.code != 1 {
		t.Fatalf("verify truncated bundle exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if strings.Contains(res.stderr, "panic:") || strings.Contains(res.stdout, "panic:") {
		t.Fatalf("CLI panicked on malformed input:\nstderr:\n%s\nstdout:\n%s", res.stderr, res.stdout)
	}
}

// TestCLIVerifyMixedUpWorkerIDsFails moves a record from one worker to another
// so the sidecar disagrees with the bundle about who measured what; the CLI
// must reject it.
func TestCLIVerifyMixedUpWorkerIDsFails(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	recs := vbRecords("w1", 5)
	bundlePath, samplesPath, ordered := vbWritePack(t, coord, worker, "w1", recs)

	// Re-label one record as belonging to a worker the bundle does not know.
	moved := append([]attest.Record(nil), ordered...)
	moved[0].Worker = "w9"

	f, err := os.Create(samplesPath)
	if err != nil {
		t.Fatalf("recreate sidecar: %v", err)
	}
	if err := attest.WriteSamples(f, moved); err != nil {
		_ = f.Close()
		t.Fatalf("WriteSamples(moved): %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close sidecar: %v", err)
	}

	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath)
	if res.code != 1 {
		t.Fatalf("verify with mixed-up worker ids exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
}

// -----------------------------------------------------------------------------
// small helpers
// -----------------------------------------------------------------------------

// flipFirstHex returns s with its first hex digit replaced by a different one,
// preserving case and length.
func flipFirstHex(s string) string {
	if s == "" {
		return s
	}
	c := s[0]
	repl := byte('0')
	if c == '0' {
		repl = '1'
	}
	return string(repl) + s[1:]
}
