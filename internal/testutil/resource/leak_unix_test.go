//go:build unix

package resource

import (
	"os"
	"testing"
	"time"
)

func TestLeakSampleDiffs(t *testing.T) {
	t.Parallel()
	before := LeakSample{Goroutines: 3, OpenFDs: 10}
	after := LeakSample{Goroutines: 8, OpenFDs: 12}
	if got := before.GoroutineDiff(after); got != 5 {
		t.Errorf("GoroutineDiff = %d, want 5", got)
	}
	if got := before.FDDiff(after); got != 2 {
		t.Errorf("FDDiff = %d, want 2", got)
	}
	for _, unreadable := range []LeakSample{{Goroutines: 1, OpenFDs: -1}} {
		if got := before.FDDiff(unreadable); got != 0 {
			t.Errorf("FDDiff with unreadable after = %d, want 0", got)
		}
		if got := unreadable.FDDiff(after); got != 0 {
			t.Errorf("FDDiff with unreadable before = %d, want 0", got)
		}
	}
}

func TestSampleSeesGoroutineAndFD(t *testing.T) {
	// Not parallel: it compares process-wide counts around a controlled change.
	before := Sample(t)
	if before.Goroutines < 1 {
		t.Fatalf("Goroutines = %d, want >= 1", before.Goroutines)
	}
	stop := make(chan struct{})
	go func() { <-stop }()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	mid := Sample(t)
	close(stop)
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if mid.Goroutines <= before.Goroutines-1 {
		t.Errorf("goroutine count did not reflect a new goroutine: before=%d mid=%d", before.Goroutines, mid.Goroutines)
	}
	if before.OpenFDs >= 0 && mid.OpenFDs < before.OpenFDs+1 {
		t.Errorf("fd count did not reflect an open file: before=%d mid=%d", before.OpenFDs, mid.OpenFDs)
	}
}

func TestWaitGoroutinesBelow(t *testing.T) {
	// Already satisfied: returns immediately at or below the target.
	if n := WaitGoroutinesBelow(1<<20, time.Second); n > 1<<20 {
		t.Errorf("returned %d above a trivially-met target", n)
	}
	// Unsatisfiable target: returns after the timeout with the current count.
	start := time.Now()
	n := WaitGoroutinesBelow(0, 20*time.Millisecond)
	if n < 1 {
		t.Errorf("count = %d, want >= 1 (the test goroutine itself)", n)
	}
	if time.Since(start) < 20*time.Millisecond {
		t.Error("returned before the timeout on an unsatisfiable target")
	}
}
