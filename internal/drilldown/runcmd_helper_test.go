package drilldown

import (
	"context"
	"errors"
	"testing"
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

// errNotFound is a stand-in for the "command not found" error exec.Command
// returns; only its non-nilness matters to the code under test.
var errNotFound = errors.New("executable file not found in $PATH")
