//go:build unix

package resource

import (
	"os"
	"runtime"
	"testing"
	"time"
)

// This file adds the one meter the DL1 resource helper deliberately left out
// (see resource.go's package doc: "It measures goroutine count, not
// file-descriptor count"). The NFL1 target measures a collector that abandons a
// goroutine blocked in an uncancellable syscall, so it must bound BOTH the
// goroutine count AND — for collectors that hold an fd while blocked (a FIFO
// open, a readdir handle) — the open-fd count across repeated calls. A pure
// goroutine meter would miss an fd leak that happens without a goroutine leak,
// and vice versa, so the NFL1 oracle needs both numbers from one sample.
//
// What this does NOT verify: it counts entries under /proc/self/fd (process-wide
// open descriptors) and runtime.NumGoroutine() (live goroutines). It cannot
// attribute either to a specific collector — a parallel test goroutine or a lazy
// runtime background goroutine moves the number too. The NFL1 target controls for
// that by running the measured path serially against a fake source and comparing
// a BEFORE/AFTER delta on the same goroutine, not an absolute count; the per-call
// drift from runtime noise is tiny next to the N-per-call leak it looks for. It
// does not see kernel-side D-state threads that no longer have a Go goroutine, nor
// fds held by another process.

// LeakSample is a point-in-time count of live goroutines and open file
// descriptors for the current process.
type LeakSample struct {
	Goroutines int
	OpenFDs    int
}

// Sample reads the current goroutine and open-fd counts. The fd count is the
// number of entries under /proc/self/fd; os.ReadDir opens, reads and closes its
// own descriptor before returning, so the transient read fd is not counted.
// Returns OpenFDs == -1 if /proc/self/fd is unreadable (non-Linux unix), so a
// caller can fall back to a goroutine-only assertion.
func Sample(t testing.TB) LeakSample {
	t.Helper()
	fds := -1
	if ents, err := os.ReadDir("/proc/self/fd"); err == nil {
		fds = len(ents)
	}
	return LeakSample{Goroutines: runtime.NumGoroutine(), OpenFDs: fds}
}

// GoroutineDiff is after.Goroutines - before.Goroutines.
func (before LeakSample) GoroutineDiff(after LeakSample) int {
	return after.Goroutines - before.Goroutines
}

// FDDiff is after.OpenFDs - before.OpenFDs, or 0 when either sample lacked a
// readable /proc/self/fd (so an unavailable meter never fabricates a leak).
func (before LeakSample) FDDiff(after LeakSample) int {
	if before.OpenFDs < 0 || after.OpenFDs < 0 {
		return 0
	}
	return after.OpenFDs - before.OpenFDs
}

// WaitGoroutinesBelow polls until runtime.NumGoroutine() drops to target or
// below, or timeout elapses; it returns the final count. Use it AFTER releasing
// deliberately-blocked goroutines (e.g. closing a fake source's release channel)
// so one fuzz iteration's abandoned goroutines drain before the next starts —
// without this a forever-blocking fake would accumulate goroutines across the
// whole fuzz run and OOM the shared host. It does not fail the test; the caller
// decides what an un-drained count means.
func WaitGoroutinesBelow(target int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		runtime.Gosched()
		n := runtime.NumGoroutine()
		if n <= target || time.Now().After(deadline) {
			return n
		}
		time.Sleep(2 * time.Millisecond)
	}
}
