package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestWithLock_MutualExclusion proves withLock actually serializes concurrent
// callers: two goroutines racing to enter their critical section must never
// both be inside it at once. A generous hold time makes an unsynchronized
// overlap near-certain to be observed if the lock isn't working.
func TestWithLock_MutualExclusion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")

	var mu sync.Mutex
	inCritical := false
	overlapped := false

	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			_ = withLock(path, func() error {
				mu.Lock()
				if inCritical {
					overlapped = true
				}
				inCritical = true
				mu.Unlock()

				time.Sleep(50 * time.Millisecond)

				mu.Lock()
				inCritical = false
				mu.Unlock()
				return nil
			})
		}()
	}
	wg.Wait()

	if overlapped {
		t.Error("two withLock critical sections ran concurrently — flock did not serialize them")
	}
}

// TestPersistAndPrune_ConcurrentNoDataLoss is the regression test for
// internal-store-01-01: Prune's os.Rename swaps what path refers to, so an
// unsynchronized Append racing a Prune can write through a stale fd to an
// inode nobody can read anymore once its holder closes it — an entry lost
// with no error surfaced by either side. maxEntries is set well below the
// total appended so Prune's rename path actually fires on nearly every call,
// not just the accounting fast path.
//
// The invariant: however goroutines interleave, PersistAndPrune serializes
// every Append against every Prune (via withLock), so the store converges to
// EXACTLY maxEntries surviving entries — never fewer. Fewer would mean an
// entry vanished through the race this fix closes.
func TestPersistAndPrune_ConcurrentNoDataLoss(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "store.jsonl")
	ctx := context.Background()

	const goroutines = 8
	const perGoroutine = 6
	const maxEntries = 10 // < goroutines*perGoroutine (48) — forces real pruning renames

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range perGoroutine {
				e := Entry{
					Hostname:  "h",
					Timestamp: time.Now(),
					Verdict:   "OK",
				}
				if err := PersistAndPrune(ctx, path, e, "h", maxEntries); err != nil {
					t.Errorf("PersistAndPrune (goroutine %d, iter %d): %v", g, i, err)
				}
			}
		}(g)
	}
	wg.Wait()

	entries, err := ReadAll(path, "h", 0)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != maxEntries {
		t.Errorf("expected exactly %d surviving entries after %d concurrent PersistAndPrune calls (proves none were silently orphaned by a racing rename), got %d",
			maxEntries, goroutines*perGoroutine, len(entries))
	}
}
