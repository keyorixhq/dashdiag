package drilldown

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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

	got, err := dirSize(dir)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	if got != 350 {
		t.Errorf("dirSize() = %d, want 350", got)
	}
}

func TestDirSize_NonexistentPath(t *testing.T) {
	t.Parallel()
	_, err := dirSize(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Errorf("dirSize() on a missing path should not error (WalkDir swallows the root error internally): got %v", err)
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
