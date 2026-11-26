// Package resource is the one place DL1 fuzz targets measure per-input cost.
//
// Andrei's standing requirement for the DL1 sweep: every fuzz target must bound
// bytes allocated, wall time and goroutine growth per input, and — where the
// target touches the filesystem — must prove the on-disk tree did not change
// (the read-only claim). The helper lives here so no target copies it.
//
// The allocation metric is the delta of runtime.MemStats.TotalAlloc across the
// measured call. TotalAlloc is cumulative and never decreases, so the delta is
// the number of bytes the call allocated regardless of whether the GC ran
// during it — the honest "how much did this input make us allocate" number, not
// a heap high-water mark. ReadMemStats stops the world, so Check reads it twice
// per input; for the string-sized inputs these targets use that cost is far
// below the per-input work and does not dominate the fuzzer. A target whose
// inputs are large enough that this shows up should switch to sampling (measure
// one input in N) — documented per target, not hidden here.
//
// What this package does NOT verify: it measures the Go heap only (TotalAlloc),
// not off-heap/mmap/cgo allocation, not RSS, not kernel memory. It measures
// goroutine count, not file-descriptor count — the DL1 in-process targets
// (string rendering, YAML decode, path validation) open no descriptors, so an
// fd oracle would be dead weight; a target that opens files must assert its own
// fd budget. Wall time is real time on a shared, thermally-throttled host, so
// the time bound is a generous ceiling that catches hangs and super-linear
// blow-ups, not a micro-benchmark.
package resource

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/fuzzutil"
)

// AllocFloor is added to every allocation budget so a tiny input still has
// headroom for fixed per-call overhead (decoder scratch, a strings.Builder).
const AllocFloor = 1 << 20 // 1 MiB

// TimeBudget is the fixed wall-time ceiling for a single input. The fuzz worker
// is killed after ~10 s on one input; this fails first, with a useful message,
// well under that.
const TimeBudget = 5 * time.Second

// Report is the measured cost of one fuzzed call.
type Report struct {
	InputLen      int
	AllocBytes    uint64        // TotalAlloc delta — bytes allocated by fn
	Elapsed       time.Duration // wall time of fn
	GoroutineDiff int           // NumGoroutine after minus before
	Amplification float64       // AllocBytes / InputLen (0 when InputLen == 0)
}

// Budget returns the allocation ceiling for an input of inputLen bytes:
// factor*inputLen + AllocFloor. factor is calibrated per target from a baseline
// run and documented in that target's file header; the DL1 default is 64.
func Budget(inputLen, factor int) uint64 {
	return uint64(factor)*uint64(inputLen) + AllocFloor
}

// Measure runs fn once and returns its cost. It does not assert anything, so a
// caller can collect the peak amplification / slowest input even when nothing
// breaches a budget (a high ratio with no failure is still a lead).
func Measure(inputLen int, fn func()) Report {
	var before, after runtime.MemStats
	g0 := runtime.NumGoroutine()
	runtime.ReadMemStats(&before)
	start := time.Now()
	fn()
	elapsed, _ := fuzzutil.EffectiveElapsed(start) // freeze-corrected: a frozen box is not a slow target
	runtime.ReadMemStats(&after)
	g1 := runtime.NumGoroutine()

	alloc := after.TotalAlloc - before.TotalAlloc
	amp := 0.0
	if inputLen > 0 {
		amp = float64(alloc) / float64(inputLen)
	}
	return Report{
		InputLen:      inputLen,
		AllocBytes:    alloc,
		Elapsed:       elapsed,
		GoroutineDiff: g1 - g0,
		Amplification: amp,
	}
}

// Check is Measure plus the budget assertions. It fails the test (t.Fatalf,
// printing input size, bytes allocated, amplification ratio and elapsed time)
// when fn allocates more than Budget(inputLen, factor) or runs longer than
// TimeBudget. factor is the calibrated per-target amplification ceiling.
func Check(t testing.TB, inputLen, factor int, fn func()) Report {
	t.Helper()
	r := Measure(inputLen, fn)
	if budget := Budget(inputLen, factor); r.AllocBytes > budget {
		t.Fatalf("allocation over budget: input=%d B, allocated=%d B, amplification=%.1fx, budget=%d B (factor %dx + %d B floor), elapsed=%s",
			r.InputLen, r.AllocBytes, r.Amplification, budget, factor, AllocFloor, r.Elapsed)
	}
	if r.Elapsed > TimeBudget {
		t.Fatalf("time over budget: input=%d B, elapsed=%s, budget=%s, allocated=%d B (%.1fx)",
			r.InputLen, r.Elapsed, TimeBudget, r.AllocBytes, r.Amplification)
	}
	return r
}

// String renders a Report for logging a peak/slowest lead in a report.
func (r Report) String() string {
	return fmt.Sprintf("input=%d B alloc=%d B amp=%.1fx elapsed=%s goroutineΔ=%d",
		r.InputLen, r.AllocBytes, r.Amplification, r.Elapsed, r.GoroutineDiff)
}
