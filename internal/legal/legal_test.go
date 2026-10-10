package legal

import (
	"path/filepath"
	"runtime"
	"testing"
)

// repoRoot resolves the module root from this test file's location
// (internal/legal/legal_test.go -> ../..).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// TestLicensingContract is the evidence test for the open-core licensing
// policy: it fails if LICENSE is not Apache-2.0, if any shipped artifact still
// references the deprecated AGPL identifier, or if NOTICE does not cover every
// third-party module compiled into the binaries.
func TestLicenseFileIsApache2(t *testing.T) {
	if err := checkLicenseFile(repoRoot(t)); err != nil {
		t.Fatalf("LICENSE check failed: %v", err)
	}
}

func TestNoDeprecatedLicenseInShippedFiles(t *testing.T) {
	if err := checkNoDeprecatedLicense(repoRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func TestNoticeCoversCompiledModules(t *testing.T) {
	if err := checkNoticeModules(repoRoot(t)); err != nil {
		t.Fatal(err)
	}
}

// TestCheckIsSelfConsistent guards against the individual checks being wired
// up wrongly (for example a shippedFiles list pointing at a file that does not
// exist).
func TestCheck(t *testing.T) {
	if err := Check(repoRoot(t)); err != nil {
		t.Fatalf("licensing contract violated: %v", err)
	}
}

// TestCompiledModulesSanity pins the third-party module set so an accidental
// dependency swap that is not reflected in NOTICE fails loudly.
func TestCompiledModulesSanity(t *testing.T) {
	modules, err := compiledModules(repoRoot(t))
	if err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}

	required := []string{
		"github.com/google/gopacket",
		"github.com/gorilla/websocket",
		"github.com/refraction-networking/utls",
		"golang.org/x/crypto",
		"google.golang.org/grpc",
		"google.golang.org/protobuf",
		"gopkg.in/yaml.v3",
	}

	have := make(map[string]bool, len(modules))
	for _, m := range modules {
		have[m] = true
	}
	for _, want := range required {
		if !have[want] {
			t.Errorf("expected compiled module %q is missing from go list -deps", want)
		}
	}
}
