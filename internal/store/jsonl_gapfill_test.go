package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStorePath_Root covers the os.Getuid() == 0 branch in StorePath.
// This path returns /var/lib/dashdiag/store.jsonl when running as root.
// The TestStorePath_NonRoot test skips when root; this test skips when non-root.
func TestStorePath_Root(t *testing.T) {
	t.Parallel()
	if os.Getuid() != 0 {
		t.Skip("running as non-root; skipping root path test")
	}
	p := StorePath()
	if p != "/var/lib/dashdiag/store.jsonl" {
		t.Errorf("StorePath as root = %q, want /var/lib/dashdiag/store.jsonl", p)
	}
}

// TestOpen_MkdirAllFails covers the os.MkdirAll error return in Open.
// Passing a path whose first directory component is an existing regular file
// makes MkdirAll fail with ENOTDIR before OpenFile is ever called.
func TestOpen_MkdirAllFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Create a regular file where a directory component must exist.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Open needs MkdirAll(blocker/sub) which fails: blocker is a file, not a dir.
	_, err := Open(filepath.Join(blocker, "sub", "store.jsonl"))
	if err == nil {
		t.Error("expected error from Open when MkdirAll cannot create parent dir")
	}
}

// TestOpen_OpenFileFails covers the os.OpenFile error return in Open.
// Creating a directory at exactly the target file path causes OpenFile to fail
// with EISDIR (O_WRONLY on a directory is not allowed).
func TestOpen_OpenFileFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Create a directory where the store file should be created.
	isDir := filepath.Join(dir, "store.jsonl")
	if err := os.Mkdir(isDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Open must fail: the path exists but is a directory, not a writable file.
	_, err := Open(isDir)
	if err == nil {
		t.Error("expected error from Open when target path is a directory")
	}
}

// TestAppend_WriteError covers the s.f.Write error return in Append.
// By closing the underlying file directly (accessible because the test is in
// the same package), the next Write call fails with "write on closed file".
func TestAppend_WriteError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "store.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	// Close the underlying OS file to make the next Write fail.
	if closeErr := s.f.Close(); closeErr != nil {
		t.Fatalf("pre-test f.Close: %v", closeErr)
	}
	err = s.Append(context.Background(), Entry{Hostname: "h", Verdict: "OK"})
	if err == nil {
		t.Error("expected error from Append after underlying file is closed")
	}
}

// TestClose_SyncError covers the s.f.Sync error return in Close.
// Closing the underlying file before calling Close causes Sync to fail.
func TestClose_SyncError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "store.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	// Close the underlying file so Sync fails.
	if closeErr := s.f.Close(); closeErr != nil {
		t.Fatalf("pre-test f.Close: %v", closeErr)
	}
	err = s.Close()
	if err == nil {
		t.Error("expected error from Close after underlying file is already closed")
	}
}

// TestHistory_ScannerError covers the sc.Err() != nil branch in History:
// a line longer than the 64 KB scanner buffer limit triggers bufio.ErrTooLong,
// which History must surface as a non-nil error rather than silently skipping it.
func TestHistory_ScannerError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store.jsonl")
	s, err := Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	// Write a line that exceeds the 64 KB scanner buffer (65 KB of JSON-like content).
	longLine := `{"hostname":"h","verdict":"OK","value":"` + strings.Repeat("x", 65*1024) + `"}`
	if err := os.WriteFile(storePath, []byte(longLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, histErr := s.History(context.Background(), "h", 10)
	if histErr == nil {
		t.Error("History must return an error when scanner hits a line exceeding the buffer limit")
	}
}

// TestHistory_FileNotExist covers the os.IsNotExist branch in History (line 72):
// when the store file has been removed after the store was opened, History must
// return (nil, nil) rather than an error — the caller treats a missing history
// file the same as an empty one.
func TestHistory_FileNotExist(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store.jsonl")
	s, err := Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.f.Close() }()
	// Delete the store file so the next History read triggers ENOENT.
	if err := os.Remove(storePath); err != nil {
		t.Fatal(err)
	}
	entries, histErr := s.History(context.Background(), "host1", 10)
	if histErr != nil {
		t.Errorf("History with missing file must return nil error (treated as empty), got %v", histErr)
	}
	if len(entries) != 0 {
		t.Errorf("History with missing file must return empty slice, got %v", entries)
	}
}

// TestHistory_NonNotExistError covers the non-IsNotExist error branch in History.
// After opening a store, we replace the directory component of the store file's
// path with a regular file. The subsequent os.Open call in History fails with
// ENOTDIR (the path component is a file, not a dir), which is not os.IsNotExist,
// so History must return a non-nil error.
func TestHistory_NonNotExistError(t *testing.T) {
	dir := t.TempDir()
	nestDir := filepath.Join(dir, "nested")
	storePath := filepath.Join(nestDir, "store.jsonl")
	s, err := Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	// Remove the store file and the nested directory, then recreate nested as a
	// regular file so that os.Open(storePath) fails with ENOTDIR.
	if err := os.Remove(storePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(nestDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nestDir, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	// s.f is now a closed-ish handle but f.Name() still returns storePath.
	// History uses f.Name() to open the file for reading; that open fails ENOTDIR.
	_, histErr := s.History(context.Background(), "h", 10)
	if histErr == nil {
		t.Error("expected non-nil error from History when path component is a file")
	}
	// Clean up: restore directory so t.TempDir cleanup can remove everything.
	_ = os.Remove(nestDir)
	_ = os.Mkdir(nestDir, 0o755)
	_ = s.f.Close()
}
