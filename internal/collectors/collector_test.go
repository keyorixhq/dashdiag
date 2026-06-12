package collectors

import (
	"context"
	"testing"
)

// runCmdOutput must return stdout even when the command exits non-zero — the
// whole point is to capture findings from tools (rpm -V, dnf check) that signal
// discrepancies via a non-zero exit while printing them to stdout. runCmd
// discards that output, which is the false-OK this helper exists to prevent.
func TestRunCmdOutputKeepsStdoutOnNonZeroExit(t *testing.T) {
	ctx := context.Background()

	out, err := runCmdOutput(ctx, "sh", "-c", "echo findings; exit 1")
	if err == nil {
		t.Error("expected a non-nil error for exit 1")
	}
	if out != "findings\n" {
		t.Errorf("runCmdOutput dropped stdout on non-zero exit: got %q, want %q", out, "findings\n")
	}

	// Contrast: runCmd discards stdout on the same non-zero exit (documents why
	// the integrity collector must use runCmdOutput).
	if dropped, _ := runCmd(ctx, "sh", "-c", "echo findings; exit 1"); dropped != "" {
		t.Errorf("runCmd unexpectedly preserved stdout: %q", dropped)
	}

	// Clean exit still returns stdout.
	if ok, err := runCmdOutput(ctx, "sh", "-c", "echo clean"); err != nil || ok != "clean\n" {
		t.Errorf("runCmdOutput clean exit: got (%q, %v)", ok, err)
	}
}
