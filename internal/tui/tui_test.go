package tui

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsTTY_RegularFile verifies IsTTY() returns false when stdin is a
// regular file (not a character device) — the common case for piped/
// redirected input and for any non-interactive test process.
func TestIsTTY_RegularFile(t *testing.T) {
	// Swaps the package-global os.Stdin — cannot run in parallel with other
	// tests in this file that also swap it.
	dir := t.TempDir()
	path := filepath.Join(dir, "stdin.txt")
	if err := os.WriteFile(path, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = old })

	if IsTTY() {
		t.Error("IsTTY() = true, want false for a regular file stdin")
	}
}

// TestIsTTY_StatError verifies IsTTY() returns false (not a panic) when
// Stat() on stdin fails — simulated by handing it an already-closed file.
func TestIsTTY_StatError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "closed.txt")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = old })

	if IsTTY() {
		t.Error("IsTTY() = true, want false when Stat() errors on a closed file")
	}
}

// TestIsTTY_Pipe verifies IsTTY() returns false when stdin is an os.Pipe
// reader, another common non-interactive-input shape (e.g. shell pipes).
func TestIsTTY_Pipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })

	if IsTTY() {
		t.Error("IsTTY() = true, want false for a pipe stdin")
	}
}
