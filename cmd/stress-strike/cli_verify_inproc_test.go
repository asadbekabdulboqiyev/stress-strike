package main

// cli_verify_inproc_test.go — in-process coverage for `stress-strike keygen`
// and `stress-strike verify`.
//
// keygen and verify call exitProcess (the new seam) directly, so they can be
// driven inside the test process without spawning the binary. A valid bundle is
// built with the same helpers the black-box tests use (vbBuildBundle etc.) so
// the whole verify path — load, signature check, Merkle recompute, aggregates,
// CI — executes for real.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
)

// writeBundleToFile persists a signed bundle and returns its path.
func writeBundleToFile(t *testing.T, b attest.Bundle) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.json")
	if err := attest.SaveBundle(b, path); err != nil {
		t.Fatalf("SaveBundle: %v", err)
	}
	return path
}

func TestInprocKeygenHappyPath(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "coord.key")

	res := runCommandFn(t, func() { cmdKeygen() }, "keygen", "--out", keyPath)
	if res.code != 0 {
		t.Fatalf("keygen exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(res.stdout), "public key: ") {
		t.Errorf("stdout = %q, want 'public key: <hex>'", res.stdout)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if runtime.GOOS != "windows" {
		// POSIX permission bits do not exist on Windows: the mode is
		// reported as 0666 and only the read-only bit is meaningful.
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("key file mode = %o, want 0600", perm)
		}
	}

	// The advertised key must match what's on disk.
	line := strings.TrimSpace(res.stdout)
	if len(line) != len("public key: ")+64 {
		t.Errorf("public key line = %q, want 64 hex chars", line)
	}
	kp, err := attest.LoadKeypairPEM(keyPath)
	if err != nil {
		t.Fatalf("LoadKeypairPEM: %v", err)
	}
	if got := attest.PublicKeyHex(kp.Public); !strings.HasSuffix(line, got) {
		t.Errorf("printed key %q does not match the file's key %q", line, got)
	}

	// Without --force, re-running must fail closed.
	res2 := runCommandFn(t, func() { cmdKeygen() }, "keygen", "--out", keyPath)
	if res2.code == 0 {
		t.Errorf("keygen without --force exit = 0, want non-zero (stderr: %s)", res2.stderr)
	}

	// With --force it overwrites.
	res3 := runCommandFn(t, func() { cmdKeygen() }, "keygen", "--out", keyPath, "--force")
	if res3.code != 0 {
		t.Fatalf("keygen --force exit = %d, want 0 (stderr: %s)", res3.code, res3.stderr)
	}
}

func TestInprocKeygenUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no out", []string{"keygen"}, "Usage:"},
		{"out empty", []string{"keygen", "--out", ""}, "Usage:"},
		{"extra positional", []string{"keygen", "--out", filepath.Join(t.TempDir(), "k"), "extra"}, "Usage:"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res := runCommandFn(t, func() { cmdKeygen() }, tc.args...)
			if res.code != 1 {
				t.Fatalf("exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, tc.want) {
				t.Errorf("stderr = %q, want %q", res.stderr, tc.want)
			}
		})
	}
}

func TestInprocVerifyValidBundle(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	b := vbBuildBundle(t, coord, worker, "w1", vbRecords("w1", 5))
	bundlePath := writeBundleToFile(t, b)

	res := runCommandFn(t, func() { cmdVerify() }, "verify", "--bundle", bundlePath)
	if res.code != 0 {
		t.Fatalf("verify exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "PASS") {
		t.Errorf("stdout = %q, want PASS", res.stdout)
	}
	if !strings.Contains(res.stdout, "bundle is valid") {
		t.Errorf("stdout = %q, want the valid message", res.stdout)
	}
}

func TestInprocVerifyJSON(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	b := vbBuildBundle(t, coord, worker, "w1", vbRecords("w1", 5))
	bundlePath := writeBundleToFile(t, b)

	res := runCommandFn(t, func() { cmdVerify() }, "verify", "--bundle", bundlePath, "--json")
	if res.code != 0 {
		t.Fatalf("verify --json exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	var got verifyJSON
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("--json is not valid JSON: %v\n%s", err, res.stdout)
	}
	if !got.Valid || got.ChecksFailed != 0 {
		t.Fatalf("report is not clean: %+v", got)
	}
	if got.Bundle != bundlePath {
		t.Errorf("Bundle = %q, want %q", got.Bundle, bundlePath)
	}
}

func TestInprocVerifyWithSidecar(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	dir := t.TempDir()
	b := vbBuildBundle(t, coord, worker, "w1", vbRecords("w1", 5))
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := attest.SaveBundle(b, bundlePath); err != nil {
		t.Fatalf("SaveBundle: %v", err)
	}
	samplesPath := filepath.Join(dir, "bundle.samples.jsonl")
	f, err := os.Create(samplesPath)
	if err != nil {
		t.Fatalf("create sidecar: %v", err)
	}
	if err := attest.WriteSamples(f, vbRecords("w1", 5)); err != nil {
		_ = f.Close()
		t.Fatalf("WriteSamples: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close sidecar: %v", err)
	}

	res := runCommandFn(t, func() { cmdVerify() }, "verify", "--bundle", bundlePath, "--samples", samplesPath)
	if res.code != 0 {
		t.Fatalf("verify with sidecar exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "PASS") {
		t.Errorf("stdout = %q, want PASS", res.stdout)
	}
}

func TestInprocVerifyUsageAndLoadErrors(t *testing.T) {
	home := scanCLIHome(t)
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no bundle", []string{"verify"}, 1, "Usage:"},
		{"missing file", []string{"verify", "--bundle", filepath.Join(home, "nope.json")}, 1, "error:"},
		{"not a bundle", func() []string {
			p := filepath.Join(home, "notabundle.json")
			if err := os.WriteFile(p, []byte(`{"not":"vpmp/v1"}`), 0o644); err != nil {
				panic(err)
			}
			return []string{"verify", "--bundle", p}
		}(), 1, "bundle is not valid"},
		{"extra positional", []string{"verify", "--bundle", filepath.Join(home, "x.json"), "extra"}, 1, "Usage:"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res := runCommandFn(t, func() { cmdVerify() }, tc.args...)
			if res.code != tc.code {
				t.Fatalf("exit = %d, want %d (stderr: %s)", res.code, tc.code, res.stderr)
			}
			needle := tc.want
			if !strings.Contains(res.stderr, needle) && !strings.Contains(res.stdout, needle) {
				t.Errorf("neither stream contains %q:\nstdout: %s\nstderr: %s", needle, res.stdout, res.stderr)
			}
		})
	}
}

func TestInprocVerifyInvalidBundleFails(t *testing.T) {
	// A file that looks like JSON but is not a valid vpmp/v1 bundle must fail
	// closed with exit 1 rather than crash.
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte(`{"format":"vpmp/v1","signature":{}}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := runCommandFn(t, func() { cmdVerify() }, "verify", "--bundle", p)
	if res.code == 0 {
		t.Fatalf("verify exit = 0, want non-zero for an invalid bundle (stdout: %s)", res.stdout)
	}
	if !strings.Contains(res.stdout, "FAIL") {
		t.Errorf("stdout = %q, want the FAIL verdict", res.stdout)
	}
}

func TestInprocVerifyExpectKeyMismatch(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath := writeBundleToFile(t, vbBuildBundle(t, coord, worker, "w1", vbRecords("w1", 1)))

	res := runCommandFn(t, func() { cmdVerify() }, "verify", "--bundle", bundlePath, "--expect-key", "deadbeef")
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "does not match the pinned key") {
		t.Errorf("stderr = %q, want the key-mismatch message", res.stderr)
	}
}
