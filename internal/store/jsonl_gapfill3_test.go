package store

// jsonl_gapfill3_test.go — closes further error-path coverage gaps found by a
// follow-up coverage audit: PersistAndPrune's Open/Append failure branches,
// Prune's ReadAll failure branch, and withLock's non-ELOOP OpenFile failure
// branch. PersistAndPrune's own Prune-fails branch and Close-fails branch,
// and Prune's post-CreateTemp write/flush/sync/rename failure branches, are
// not covered here — reaching them needs OS-level fault injection (a write
// that succeeds at CreateTemp but fails on the very next syscall) with no
// clean, portable way to trigger it through the public API; see
// TestPrune_CreateTempFails in jsonl_gapfill2_test.go for the one such branch
// that IS reachable this way.

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPersistAndPrune_OpenError covers PersistAndPrune's Open-fails branch:
// path="" is the StorePath()-unresolved sentinel Open() refuses immediately.
// withLock still runs first and creates its sidecar lock file at
// ""+".lock" = ".lock" in the process's CWD before the inner Open("") ever
// fails — clean that up so the test leaves no droppings.
func TestPersistAndPrune_OpenError(t *testing.T) {
	t.Cleanup(func() { _ = os.Remove(".lock") })
	err := PersistAndPrune(context.Background(), "", Entry{Hostname: "h", Verdict: "OK"}, "h", 10)
	if err == nil {
		t.Fatal("expected an error from PersistAndPrune with an empty path, got nil")
	}
	if !strings.Contains(err.Error(), "cannot determine store path") {
		t.Errorf("PersistAndPrune(\"\") = %v, want the Open(\"\") sentinel error", err)
	}
}

// TestPersistAndPrune_AppendError covers PersistAndPrune's Append-fails
// branch: a NaN metric makes json.Marshal fail inside Append, which must
// still Close the store (releasing the fd/lock) before returning the error —
// verified here by a second, valid PersistAndPrune on the same path
// succeeding right after.
func TestPersistAndPrune_AppendError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")

	nanEntry := Entry{Hostname: "h", Verdict: "OK", Metrics: map[string]float64{"bad": math.NaN()}}
	err := PersistAndPrune(context.Background(), path, nanEntry, "h", 10)
	if err == nil {
		t.Fatal("expected an error from PersistAndPrune with a NaN metric, got nil")
	}
	if !strings.Contains(err.Error(), "marshalling entry") {
		t.Errorf("PersistAndPrune(NaN entry) = %v, want a marshalling error", err)
	}

	// The failed Append must not have leaked the fd or left the cross-process
	// lock held — a follow-up call with a valid entry must succeed cleanly.
	if err := PersistAndPrune(context.Background(), path, Entry{Hostname: "h", Verdict: "OK"}, "h", 10); err != nil {
		t.Errorf("PersistAndPrune after a prior Append failure: %v, want nil (Close must still run on the error path)", err)
	}
}

// TestPrune_ReadAllError covers Prune's ReadAll-fails branch: path pointing
// at a directory opens successfully (os.Open follows directories) but fails
// on the first Read, which ReadAll surfaces as a non-nil, non-EOF error.
func TestPrune_ReadAllError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dirPath := filepath.Join(dir, "not-a-file")
	if err := os.Mkdir(dirPath, 0o750); err != nil {
		t.Fatal(err)
	}

	err := Prune(dirPath, "h", 10)
	if err == nil {
		t.Fatal("expected an error from Prune when path is a directory, got nil")
	}
	if !strings.Contains(err.Error(), "reading") {
		t.Errorf("Prune(directory path) = %v, want a 'reading' error propagated from ReadAll", err)
	}
}

// TestWithLock_OpenFileGenericError covers withLock's non-ELOOP OpenFile
// failure branch: a directory sitting at the lock path itself (as opposed to
// a missing parent, or a symlink) makes OpenFile fail with EISDIR.
func TestWithLock_OpenFileGenericError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")
	if err := os.Mkdir(path+".lock", 0o750); err != nil {
		t.Fatal(err)
	}

	err := withLock(path, func() error { return nil })
	if err == nil {
		t.Fatal("expected an error from withLock when the lock path is a directory, got nil")
	}
	if !strings.Contains(err.Error(), "opening lock") {
		t.Errorf("withLock() = %v, want an 'opening lock' error", err)
	}
}
