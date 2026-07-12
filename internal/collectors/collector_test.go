package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestActiveSource guards the accessor's wiring: it must always return
// whatever SetSource last installed, never a stale or default value.
func TestActiveSource(t *testing.T) {
	fake := source.NewReplay(source.NewBundle())
	prev := SetSource(fake)
	defer SetSource(prev)

	if ActiveSource() != fake {
		t.Error("ActiveSource() did not return the source installed by SetSource")
	}
}

// TestSetSource_PreviousNil guards the defensive prev==nil branch: SetSource
// must return nil (not panic dereferencing a nil *source.Source) when the
// package-level activeSource pointer was itself nil beforehand. In production
// init() always seeds a real value, so this only exercises the safety check —
// deliberately pokes the unexported atomic.Pointer directly (same package),
// which is why this test must NOT run in parallel with anything else that
// touches activeSource (matches the existing no-t.Parallel convention for
// activeSource-swapping tests in this package, e.g. apache_linux_test.go).
func TestSetSource_PreviousNil(t *testing.T) {
	real := source.NewReplay(source.NewBundle())
	prevPtr := activeSource.Swap(nil)
	defer func() {
		if prevPtr != nil {
			activeSource.Store(prevPtr)
		} else {
			SetSource(real)
		}
	}()

	got := SetSource(real)
	if got != nil {
		t.Errorf("SetSource() with a nil previous pointer = %v, want nil", got)
	}
}

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
