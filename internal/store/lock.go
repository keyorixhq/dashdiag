package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// withLock serializes access to path across processes via an exclusive flock
// held on a stable sidecar lock file (path+".lock") — never on path itself.
//
// This distinction matters: Prune replaces path via os.Rename, which swaps
// what the path refers to without affecting a file descriptor a concurrent
// process already has open on the old (now-unlinked) inode. A lock keyed to
// path would let that stale fd keep writing to data nobody can read anymore
// once its holder closes it — the exact silent-data-loss race
// internal-store-01-01 describes. The lock file is never renamed or
// replaced, so its identity never changes underneath a blocked waiter: every
// caller contends for the same inode for as long as the store exists.
//
// Callers must (re)open/read/write the actual store file INSIDE fn, after
// the lock is held, so they always observe path's current, post-rename
// content rather than a handle opened before a concurrent Prune ran.
func withLock(path string, fn func() error) error {
	lockPath := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		return fmt.Errorf("store: creating lock dir: %w", err)
	}
	// O_NOFOLLOW: refuse to lock through a pre-existing symlink, same hazard
	// Open() guards for the store file itself.
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // lockPath is derived from StorePath(), not user input
	if errors.Is(err, syscall.ELOOP) {
		return fmt.Errorf("store: refusing to lock through a symlink at %s", lockPath)
	}
	if err != nil {
		return fmt.Errorf("store: opening lock %s: %w", lockPath, err)
	}
	defer func() { _ = lf.Close() }()

	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("store: locking %s: %w", lockPath, err)
	}
	defer func() { _ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) }()

	return fn()
}
