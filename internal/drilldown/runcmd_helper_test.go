package drilldown

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/platform"
)

// swapRunCmd replaces the package-level runCmd for the duration of the test.
// Callers MUST NOT also call t.Parallel(): the swap is only race-free because
// Go's test runner finishes all serial tests before starting the parallel
// batch (same constraint as the t.Setenv("HOME") tests elsewhere in this
// package/codebase).
func swapRunCmd(t *testing.T, fake func(ctx context.Context, name string, args ...string) (string, error)) {
	t.Helper()
	old := runCmd
	runCmd = fake
	t.Cleanup(func() { runCmd = old })
}

// swapLookPath replaces the package-level lookPath for the duration of the
// test. Same non-parallel constraint as swapRunCmd.
func swapLookPath(t *testing.T, fake func(file string) (string, error)) {
	t.Helper()
	old := lookPath
	lookPath = fake
	t.Cleanup(func() { lookPath = old })
}

// swapDetectContainerContext replaces the package-level detectContainerContext
// for the duration of the test. Same non-parallel constraint as swapRunCmd —
// this keeps memory.go's MEM% tests hermetic even when the test binary itself
// happens to be running inside a container (e.g. the dashdiag-dev dev
// container), rather than depending on whatever the host's real
// /.dockerenv, /proc/self/cgroup, etc. happen to say.
func swapDetectContainerContext(t *testing.T, fake func() platform.ContainerContext) {
	t.Helper()
	old := detectContainerContext
	detectContainerContext = fake
	t.Cleanup(func() { detectContainerContext = old })
}

// errNotFound is a stand-in for the "command not found" error exec.Command
// returns; only its non-nilness matters to the code under test.
var errNotFound = errors.New("executable file not found in $PATH")

// TestRunCmd_RealSubprocess exercises the actual (unswapped) package-level
// runCmd against a real subprocess — every other test in this package swaps
// it out. internal-drilldown-01-07: runCmd's stdout capture went from a
// plain unbounded bytes.Buffer to source.NewCapWriter(source.MaxCapturedOutput);
// this confirms that wiring still round-trips real output correctly (the
// cap's own enforcement at the byte level is proven independently in
// internal/source/capwriter_test.go — generating tens of MB of subprocess
// output here to exercise the cap itself would be wasteful).
func TestRunCmd_RealSubprocess(t *testing.T) {
	out, err := runCmd(context.Background(), "echo", "-n", "hello-from-real-subprocess")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello-from-real-subprocess" {
		t.Errorf("runCmd output = %q, want %q", out, "hello-from-real-subprocess")
	}
}
