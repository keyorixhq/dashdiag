package installscript

// fuzz_coverage_test.go guards against the exact bug class documented in
// docs/CONTINUOUS_FUZZING.md: a hardcoded FuzzXxx target list silently
// drifting from the module's real fuzz functions. `make test-fuzz` missed 18
// of 44 targets for months, then — after scripts/fuzz-discover.sh replaced
// the hardcoded Makefile lists with real discovery — this is what stops that
// pattern from quietly coming back (e.g. someone "optimizing" fuzz-discover.sh
// back into a static list).
//
// It compares two INDEPENDENTLY derived sets of FuzzXxx names, the same shape
// as internal/render/schema_sync_test.go (struct reflection vs. JSON schema):
//   - sourceFuzzFuncs: every func matching Go's fuzz-target signature, found
//     by scanning *_test.go source directly (go/build.MatchFile decides
//     per-file build-tag visibility — the SAME mechanism `go list`/`go test
//     -list` use, so this agrees with `go test -list` on every host without
//     needing to actually invoke it).
//   - discoveredFuzzFuncs: scripts/fuzz-discover.sh's own `all` output — the
//     actual mechanism the Makefile and CI run.
// Any mismatch means a real FuzzXxx function exists that CI would never run,
// or discovery is reporting something that doesn't exist — either way, a
// real bug, not a style nit.

import (
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var fuzzFuncRe = regexp.MustCompile(`(?m)^func (Fuzz\w+)\(f \*testing\.F\)`)

// repoRoot resolves the repo root via this file's own path (this file lives
// at the repo root by construction) — matches install_script_test.go's
// runtime.Caller(0) convention rather than relying on `go test`'s cwd.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed to resolve this test file's path")
	}
	return filepath.Dir(thisFile)
}

// sourceFuzzFuncs scans every _test.go file this host's toolchain would
// actually build (go/build.MatchFile evaluates the same //go:build
// constraints go test -list does) for a func matching Go's fuzz-target
// signature. A deliberately different method from `go test -list` — for the
// same reason schema_sync_test.go compares reflection against a JSON file
// instead of two copies of the same walk — so the two can't share a blind spot.
func sourceFuzzFuncs(t *testing.T, root string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") || info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		match, matchErr := build.Default.MatchFile(filepath.Dir(path), filepath.Base(path))
		if matchErr != nil {
			return matchErr
		}
		if !match {
			return nil // build-tag-excluded on this host — go test -list wouldn't see it either
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, m := range fuzzFuncRe.FindAllStringSubmatch(string(data), -1) {
			found[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking module for fuzz funcs: %v", err)
	}
	return found
}

// discoveredFuzzFuncs runs scripts/fuzz-discover.sh all — the same mechanism
// the Makefile and fuzz.yml use to decide what actually gets fuzzed.
func discoveredFuzzFuncs(t *testing.T, root string) map[string]bool {
	t.Helper()
	script := filepath.Join(root, "scripts", "fuzz-discover.sh")
	out, err := exec.Command(script, "all").Output()
	if err != nil {
		t.Fatalf("running %s all: %v", script, err)
	}
	found := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("unexpected scripts/fuzz-discover.sh output line: %q", line)
		}
		found[name] = true
	}
	return found
}

func TestFuzzDiscoveryCoversEverySourceFuzzFunc(t *testing.T) {
	root := repoRoot(t)
	source := sourceFuzzFuncs(t, root)
	discovered := discoveredFuzzFuncs(t, root)

	if len(source) == 0 {
		t.Fatal("sourceFuzzFuncs found zero FuzzXxx functions — the scan itself is broken, not the module")
	}

	for name := range source {
		if !discovered[name] {
			t.Errorf("%s is a real FuzzXxx function in source but scripts/fuzz-discover.sh does not report it "+
				"— it will never be run by CI (fuzz.yml) or the continuous fuzzing rig", name)
		}
	}
	for name := range discovered {
		if !source[name] {
			t.Errorf("scripts/fuzz-discover.sh reports %s but no matching source function was found "+
				"— stale or incorrect discovery output", name)
		}
	}
}
