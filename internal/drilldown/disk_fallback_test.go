package drilldown

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDirSize(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), make([]byte, 100), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b"), make([]byte, 250), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := dirSize(context.Background(), dir)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	if got != 350 {
		t.Errorf("dirSize() = %d, want 350", got)
	}
}

func TestDirSize_NonexistentPath(t *testing.T) {
	t.Parallel()
	_, err := dirSize(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Errorf("dirSize() on a missing path should not error (WalkDir swallows the root error internally): got %v", err)
	}
}

// TestDirSize_CancelledContextReturnsPromptly proves that a ctx which fires
// before (or shortly after) the walk starts makes dirSize return promptly
// with ctx.Err() rather than blocking until WalkDir finishes on its own —
// the bug this fix addresses (internal-drilldown-01-06): a single dirSize
// call previously had zero ctx awareness and could run past the caller's
// drilldown budget.
func TestDirSize_CancelledContextReturnsPromptly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Give WalkDir enough entries that, absent the ctx select, a slow
	// filesystem walk would plausibly still be running past the deadline
	// below. On a fast local tmpfs this alone won't be slow, but combined
	// with an already-cancelled context it exercises the same select
	// branch deterministically.
	for i := range 50 {
		sub := filepath.Join(dir, string(rune('a'+i%26))+string(rune('0'+i/26)))
		if err := os.MkdirAll(sub, 0755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(sub, "f"), make([]byte, 10), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	// Ensure the deadline has definitely passed before dirSize is called,
	// so the ctx.Done() branch of the select is guaranteed ready
	// immediately — this is what makes the test deterministic rather than
	// timing-sensitive.
	time.Sleep(time.Millisecond)

	start := time.Now()
	const budget = 500 * time.Millisecond
	done := make(chan struct{})
	var gotErr error
	go func() {
		_, gotErr = dirSize(ctx, dir)
		close(done)
	}()

	select {
	case <-done:
		if !errors.Is(gotErr, context.DeadlineExceeded) {
			t.Errorf("dirSize() error = %v, want context.DeadlineExceeded", gotErr)
		}
	case <-time.After(budget):
		t.Fatalf("dirSize() did not return within %s of a fired context deadline — it is blocking on WalkDir instead of selecting on ctx.Done()", budget)
	}
	if elapsed := time.Since(start); elapsed > budget {
		t.Errorf("dirSize() took %s to return after context deadline fired, want well under %s", elapsed, budget)
	}
}

// TestDirSize_EntryCapBoundsWork proves the defensive maxDirSizeWalkEntries
// cap actually trips: a directory with more files than the cap must not
// error or panic, and must return without visiting every single entry.
// The cap is a worst-case bound on background goroutine work (relevant once
// ctx cancellation has already caused the caller to stop waiting), so this
// test only asserts "doesn't error, doesn't hang" rather than an exact byte
// count — WalkDir's traversal order is not being second-guessed here.
func TestDirSize_EntryCapBoundsWork(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const fileCount = maxDirSizeWalkEntries + 500
	for i := range fileCount {
		name := filepath.Join(dir, fmt.Sprintf("f%06d", i))
		if err := os.WriteFile(name, make([]byte, 1), 0644); err != nil {
			t.Fatalf("WriteFile %d: %v", i, err)
		}
	}

	got, err := dirSize(context.Background(), dir)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	if got <= 0 {
		t.Errorf("dirSize() = %d, want a positive partial total", got)
	}
	if got >= fileCount {
		t.Errorf("dirSize() = %d, want less than the uncapped total %d (the entry cap should have stopped the walk early)", got, fileCount)
	}
}

// TestDirSize_ByteCapBoundsWork proves the defensive maxDirSizeWalkBytes cap
// trips for a directory with comparatively few but large files, the
// companion pathological shape the entry-count cap alone would miss.
func TestDirSize_ByteCapBoundsWork(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// A handful of files, each larger than the byte cap on its own, so the
	// byte cap — not the entry cap — is what must trip here. Truncate
	// creates a sparse file (logical size only) so this stays fast and
	// doesn't actually write terabytes to disk.
	for i := range 3 {
		name := filepath.Join(dir, fmt.Sprintf("big%d", i))
		f, err := os.Create(name)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := f.Truncate(maxDirSizeWalkBytes + 1<<20); err != nil {
			f.Close()
			t.Fatalf("Truncate: %v", err)
		}
		f.Close()
	}

	got, err := dirSize(context.Background(), dir)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	if got > maxDirSizeWalkBytes+2<<20 {
		t.Errorf("dirSize() = %d, want roughly bounded near maxDirSizeWalkBytes (%d); the byte cap should have stopped the walk after the first oversized file", got, int64(maxDirSizeWalkBytes))
	}
}

func TestLargestDirsFallback(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	small := filepath.Join(dir, "small")
	big := filepath.Join(dir, "big")
	if err := os.MkdirAll(small, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.MkdirAll(big, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(small, "f"), make([]byte, 10), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(big, "f"), make([]byte, 10_000), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := largestDirsFallback(context.Background(), dir)
	if err != nil {
		t.Fatalf("largestDirsFallback: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %+v", len(got.Rows), got.Rows)
	}
	if got.Rows[0][1] != big || got.Rows[1][1] != small {
		t.Errorf("expected rows sorted by size descending (big, small), got %+v", got.Rows)
	}
}

// TestLargestDirsFallback_CancelledContextStopsEarly guards the ctx.Done()
// select branch inside the per-entry loop: a context cancelled before the
// walk starts must make the very first iteration return ctx.Err() rather
// than walking every child.
func TestLargestDirsFallback_CancelledContextStopsEarly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for i := range 3 {
		sub := filepath.Join(dir, string(rune('a'+i)))
		if err := os.MkdirAll(sub, 0755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := largestDirsFallback(ctx, dir)
	if err == nil {
		t.Error("expected ctx.Err() to propagate from a pre-cancelled context")
	}
}

func TestLargestDirsFallback_NonexistentMount(t *testing.T) {
	t.Parallel()
	_, err := largestDirsFallback(context.Background(), filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Error("expected an error for a nonexistent mount, got nil")
	}
}

func TestLargestDirsFallback_CapsAtEight(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for i := range 10 {
		sub := filepath.Join(dir, string(rune('a'+i)))
		if err := os.MkdirAll(sub, 0755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(sub, "f"), make([]byte, i+1), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	got, err := largestDirsFallback(context.Background(), dir)
	if err != nil {
		t.Fatalf("largestDirsFallback: %v", err)
	}
	if len(got.Rows) != 8 {
		t.Errorf("expected rows capped at 8, got %d", len(got.Rows))
	}
}
