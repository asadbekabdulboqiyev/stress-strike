package main

// cli_sub_inproc_test.go — in-process coverage for cmd_sub.go.
//
// runSubCommand spawns sibling binaries (or `go run`), which is not hermetic,
// so only findProjectRoot is covered directly here: it walks the working
// directory upward until it finds go.mod.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInprocFindProjectRoot(t *testing.T) {
	root := findProjectRoot()
	if root == "." {
		t.Fatal("findProjectRoot returned '.', want a real directory")
	}
	mod := filepath.Join(root, "go.mod")
	if _, err := os.Stat(mod); err != nil {
		t.Errorf("findProjectRoot = %q, but %q does not exist: %v", root, mod, err)
	}
	if !strings.HasSuffix(root, "Sift") {
		t.Errorf("findProjectRoot = %q, want the Sift checkout root", root)
	}
}

// runSubCommand's executable-path error branch (os.Executable failing) cannot be
// triggered deterministically, and spawning sibling binaries is not hermetic,
// so those branches are deliberately left to the black-box subprocess tests.
