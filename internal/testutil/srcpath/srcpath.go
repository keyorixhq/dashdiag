// Package srcpath locates source files for tests that read the repository
// (static guards, AST sweeps, install.sh and fuzz-discovery checks).
//
// It exists because runtime.Caller's file name is NOT a usable filesystem path
// under `-trimpath` (GOFLAGS=-trimpath is common on developer machines and in
// agent tooling): it becomes the import path
// ("github.com/keyorixhq/dashdiag/cmd/mcp_governance_test.go"). Keep
// runtime.Caller for function names and line numbers, never for opening files.
//
// `go test` starts each test binary in the package directory. The starting
// directory is captured once at package initialisation, which runs before any
// test in the importing package and therefore before any t.Chdir, so a test
// that changes the working directory cannot move RepoRoot or PkgDir. Do not
// resolve lazily from os.Getwd() at call time.
package srcpath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const rootModule = "github.com/keyorixhq/dashdiag"

var startDir, startErr = os.Getwd()

// RepoRoot returns the absolute directory of the go.mod declaring
// github.com/keyorixhq/dashdiag. It panics if the root cannot be found, which
// only happens when a compiled test binary runs outside the repository.
func RepoRoot() string {
	if startErr != nil {
		panic("srcpath: " + startErr.Error())
	}
	root, err := findRoot(startDir)
	if err != nil {
		panic("srcpath: " + err.Error())
	}
	return root
}

// PkgDir returns the absolute directory of the package under test, as it was
// when the test binary started.
func PkgDir() string {
	if startErr != nil {
		panic("srcpath: " + startErr.Error())
	}
	return startDir
}

func findRoot(start string) (string, error) {
	dir := start
	for {
		if modulePath(filepath.Join(dir, "go.mod")) == rootModule {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod for module %s at or above %s", rootModule, start)
		}
		dir = parent
	}
}

// modulePath returns the module path declared in a go.mod file, or "" if the
// file is missing or has no module line.
func modulePath(goMod string) string {
	data, err := os.ReadFile(goMod) // #nosec G304 -- walks up from the test starting directory
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "module")
		if ok && strings.TrimLeft(rest, " \t") != rest {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}
