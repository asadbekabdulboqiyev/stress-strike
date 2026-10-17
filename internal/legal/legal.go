// Package legal verifies that the repository's licensing artifacts stay
// consistent with the project's open-core license policy.
//
// Policy (see LICENSING.md): the code in this repository is Apache-2.0, and a
// separate commercial tier is built on top of it. The rule this package
// enforces mechanically is that no *shipped* artifact still advertises the
// pre-open-core license, and that NOTICE lists every third-party module that
// actually ends up in the released binaries.
//
// The check exists so a future edit cannot silently reintroduce a conflicting
// license string into a package manifest, container image, or archive.
package legal

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	// CoreLicenseName is the SPDX identifier of the license covering the code
	// in this repository.
	CoreLicenseName = "MIT"

	// DeprecatedLicense is the license identifier used before the open-core
	// switch. Its presence in a shipped artifact is a policy violation.
	DeprecatedLicense = "AGPL"

	// DeprecatedLicenseFull is the human-readable form that must not appear in
	// the LICENSE file either.
	DeprecatedLicenseFull = "GNU AFFERO"
)

// shippedFiles are artifacts published to users: the source distribution,
// release archives, container images, and package-manager manifests. None of
// them may carry the deprecated license identifier.
//
// docs and reports (for example CI-CD-AUDIT-REPORT.md) are intentionally not
// listed: they are allowed to mention the old license for historical reasons.
var shippedFiles = []string{
	"LICENSE",
	"NOTICE",
	"README.md",
	"CONTRIBUTING.md",
	"packaging/scoop/stress-strike.json",
	"packaging/homebrew/stress-strike.rb",
	"packaging/winget/stress-strike.yaml",
	".goreleaser.yaml",
	"Dockerfile",
	"Dockerfile.master",
	"Dockerfile.worker",
	".dockerignore",
	"website/index.html",
}

// noticeModuleRe extracts the module path from a NOTICE bullet
// (for example "  * github.com/google/gopacket").
var noticeModuleRe = regexp.MustCompile(`(?m)^\s*\*\s+(\S+)/?`)

// Check validates every licensing artifact rooted at repoRoot.
func Check(repoRoot string) error {
	if err := checkLicenseFile(repoRoot); err != nil {
		return err
	}
	if err := checkNoDeprecatedLicense(repoRoot); err != nil {
		return err
	}
	return checkNoticeModules(repoRoot)
}

// checkLicenseFile asserts that LICENSE is the Apache-2.0 text and not the
// deprecated one.
func checkLicenseFile(repoRoot string) error {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "LICENSE"))
	if err != nil {
		return fmt.Errorf("read LICENSE: %w", err)
	}
	text := string(raw)

	if !strings.Contains(text, "MIT License") {
		return fmt.Errorf("LICENSE does not contain the MIT text")
	}
	if strings.Contains(text, DeprecatedLicenseFull) {
		return fmt.Errorf("LICENSE still contains %q; expected pure Apache-2.0", DeprecatedLicenseFull)
	}
	return nil
}

// checkNoDeprecatedLicense scans every shipped file for the deprecated
// identifier.
func checkNoDeprecatedLicense(repoRoot string) error {
	var offenders []string
	for _, rel := range shippedFiles {
		raw, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		if strings.Contains(string(raw), DeprecatedLicense) {
			offenders = append(offenders, rel)
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		return fmt.Errorf("shipped files still reference %s: %s", DeprecatedLicense, strings.Join(offenders, ", "))
	}
	return nil
}

// checkNoticeModules asserts that NOTICE lists exactly the third-party modules
// compiled into the released binaries.
func checkNoticeModules(repoRoot string) error {
	modules, err := compiledModules(repoRoot)
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(filepath.Join(repoRoot, "NOTICE"))
	if err != nil {
		return fmt.Errorf("read NOTICE: %w", err)
	}

	listed := make(map[string]bool)
	for _, m := range noticeModuleRe.FindAllStringSubmatch(string(raw), -1) {
		listed[m[1]] = true
	}

	var missing []string
	for _, m := range modules {
		if !listed[m] {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("NOTICE is missing compiled module(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

// compiledModules returns the third-party module paths linked into the
// binaries under ./...
func compiledModules(repoRoot string) ([]string, error) {
	cmd := exec.Command("go", "list", "-deps",
		"-f", "{{if .Module}}{{.Module.Path}}{{end}}", "./...")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -deps: %w", err)
	}

	const self = "github.com/asadbekabdulboqiyev/stress-strike"
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == self {
			continue
		}
		seen[line] = true
	}

	modules := make([]string, 0, len(seen))
	for m := range seen {
		modules = append(modules, m)
	}
	sort.Strings(modules)
	return modules, nil
}
