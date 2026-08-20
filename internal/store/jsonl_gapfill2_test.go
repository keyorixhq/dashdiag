package store

// jsonl_gapfill2_test.go — closes error-path coverage gaps found by a full
// coverage audit: withLock's MkdirAll/symlink-refusal branches and Prune's
// CreateTemp failure branch. Close's Sync error branch is already covered by
// TestClose_SyncError in jsonl_gapfill_test.go. All happy paths and several
// other error branches (missing file, below limit, etc.) already have
// coverage elsewhere in this package.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWithLock_MkdirAllFails: a regular file sitting where the lock file's
// parent directory needs to be created makes os.MkdirAll fail with ENOTDIR.
func TestWithLock_MkdirAllFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "sub", "store.jsonl") // "blocker" is a file, not a dir

	err := withLock(path, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "creating lock dir") {
		t.Errorf("withLock() = %v, want a 'creating lock dir' error", err)
	}
}

// TestWithLock_RefusesSymlinkedLockFile: a pre-existing symlink at the lock
// path must be refused (ELOOP), same hazard Open() guards for the store file
// itself — a co-located user could otherwise redirect the lock to an
// arbitrary target.
func TestWithLock_RefusesSymlinkedLockFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".lock"); err != nil {
		t.Fatal(err)
	}

	err := withLock(path, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "refusing to lock through a symlink") {
		t.Errorf("withLock() = %v, want a symlink-refusal error", err)
	}
}

// TestPrune_CreateTempFails: a read-only containing directory makes
// os.CreateTemp fail — Prune must propagate that error rather than silently
// dropping entries or corrupting the store.
func TestPrune_CreateTempFails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permission bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for range 3 {
		if err := s.Append(context.Background(), Entry{Hostname: "h", Verdict: "OK"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // let t.TempDir() clean up

	err = Prune(path, "h", 1) // 3 entries > maxEntries=1 forces the write path
	if err == nil || !strings.Contains(err.Error(), "creating temp") {
		t.Errorf("Prune() = %v, want a 'creating temp' error", err)
	}
}
