package runner

import (
	"context"
	"strings"
	"testing"
	"time"
)

// panicCollector always panics inside Collect — simulating a bug in a real
// collector (nil pointer deref on an unexpected parse result, index out of
// range, etc.).
type panicCollector struct {
	name string
}

func (p *panicCollector) Name() string           { return p.name }
func (p *panicCollector) Timeout() time.Duration { return time.Second }
func (p *panicCollector) Collect(_ context.Context) (any, error) {
	panic("simulated collector bug")
}

// TestRunAll_CollectorPanicDoesNotCrashRun is C1's runner-level requirement:
// one collector panicking must not take down the whole process (which would
// currently exit via Go's default unhandled-panic status, colliding with a
// real CRIT) and must not silently vanish from the results (which would let
// the run read as fully clean). It must surface as an ordinary Result with a
// non-nil Err, exactly like any other collector failure — so it flows through
// analysis.ApplyThresholds into an Unverified insight the same way a timeout
// or a plain error does, and the OTHER collectors in the same run must still
// deliver their real results unaffected.
func TestRunAll_CollectorPanicDoesNotCrashRun(t *testing.T) {
	collectors := []Collector{
		&panicCollector{name: "Buggy"},
		&mockCollector{name: "Fine", delay: 5 * time.Millisecond, result: "ok", timeout: time.Second},
	}

	ch := RunAll(context.Background(), collectors)
	results := collectAll(ch) // must not hang — the whole point of the test

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (panic must not drop the other collector's result)", len(results))
	}

	var buggy, fine *Result
	for i := range results {
		switch results[i].Name {
		case "Buggy":
			buggy = &results[i]
		case "Fine":
			fine = &results[i]
		}
	}

	if buggy == nil {
		t.Fatal("no result recorded for the panicking collector")
	}
	if buggy.Err == nil {
		t.Fatal("panicking collector's Result.Err is nil — a panic must surface as an error, not a silent zero-value result")
	}
	if !strings.Contains(buggy.Err.Error(), "panic") {
		t.Errorf("Result.Err = %q, want it to mention the panic", buggy.Err.Error())
	}
	if buggy.Data != nil {
		t.Errorf("panicking collector's Result.Data = %v, want nil (must not look like a real, if empty, reading)", buggy.Data)
	}

	if fine == nil {
		t.Fatal("no result recorded for the unrelated, healthy collector — one collector's panic must not affect its sibling")
	}
	if fine.Err != nil {
		t.Errorf("healthy collector's Result.Err = %v, want nil", fine.Err)
	}
	if fine.Data != "ok" {
		t.Errorf("healthy collector's Result.Data = %v, want %q", fine.Data, "ok")
	}
}
