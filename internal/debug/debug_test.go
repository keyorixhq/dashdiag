package debug_test

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/debug"
)

// captureStderr redirects os.Stderr for the duration of fn and returns what
// was written. debug.Log/Logf write directly to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = wr
	fn()
	_ = wr.Close()
	os.Stderr = old
	data, _ := io.ReadAll(rd)
	_ = rd.Close()
	return string(data)
}

func TestEnabled(t *testing.T) {
	ctx := context.Background()

	if debug.Enabled(ctx) {
		t.Fatal("expected debug disabled on plain context")
	}

	ctx = debug.With(ctx, true)
	if !debug.Enabled(ctx) {
		t.Fatal("expected debug enabled after With(ctx, true)")
	}

	ctx = debug.With(ctx, false)
	if debug.Enabled(ctx) {
		t.Fatal("expected debug disabled after With(ctx, false)")
	}
}

func TestLogDoesNotPanicWhenDisabled(t *testing.T) {
	ctx := context.Background() // debug off
	// Should be a no-op — no panic, no output.
	debug.Log(ctx, "Test", "should be silent", "key", "value")
	debug.Logf(ctx, "Test", "should be silent %s", "too")
}

func TestLogDoesNotPanicWhenEnabled(t *testing.T) {
	ctx := debug.With(context.Background(), true)
	// Writes to stderr — just verify no panic.
	debug.Log(ctx, "Test", "hello", "k1", "v1", "k2", 42)
	debug.Logf(ctx, "Test", "formatted %d", 99)
}

func TestLogOddKVSurfacesMarker(t *testing.T) {
	ctx := debug.With(context.Background(), true)
	// Odd number of kvs — should not panic, should emit MISSING_VALUE_FOR marker.
	debug.Log(ctx, "Test", "odd kv", "orphan_key")
}

// TestLogSanitizesControlChars guards Finding internal-debug-01-01: kv values
// passed to Log ultimately originate from the host being diagnosed (err
// strings from failed probes/subprocess calls, hostnames/IPs from the
// routing table) and neither Log nor Logf stripped control characters or
// ANSI/OSC escape sequences before writing to os.Stderr. An embedded
// newline could also forge a fake "[debug] ..." line to mislead the
// operator reading --debug output.
func TestLogSanitizesControlChars(t *testing.T) {
	ctx := debug.With(context.Background(), true)
	evil := "evil\x1b[2Jname\nforged [debug] line"

	out := captureStderr(t, func() {
		debug.Log(ctx, "Test", "probe failed", "err", evil)
	})
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("Log output still contains a raw ESC byte: %q", out)
	}
	// Splitting on real newlines must yield exactly one line — an embedded
	// \n in a kv value must not forge a second "[debug] ..." line.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("Log output split into %d lines (embedded newline not stripped): %q", len(lines), out)
	}
}

// TestLogfSanitizesControlChars is Log's sibling test for the printf-style
// Logf entry point.
func TestLogfSanitizesControlChars(t *testing.T) {
	ctx := debug.With(context.Background(), true)
	evil := "evil\x1b[2Jname\nforged [debug] line"

	out := captureStderr(t, func() {
		debug.Logf(ctx, "Test", "probe failed: %s", evil)
	})
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("Logf output still contains a raw ESC byte: %q", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("Logf output split into %d lines (embedded newline not stripped): %q", len(lines), out)
	}
}

func TestWithDoesNotMutateParent(t *testing.T) {
	parent := context.Background()
	child := debug.With(parent, true)

	if debug.Enabled(parent) {
		t.Fatal("With mutated parent context")
	}
	if !debug.Enabled(child) {
		t.Fatal("child should have debug enabled")
	}
}
