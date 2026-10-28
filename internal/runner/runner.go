package runner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/keyorixhq/dashdiag/internal/debug"
)

// collectGrace is how long the runner waits, after a collector's deadline fires,
// for the collector to deliver its own result before synthesizing a timeout. It
// lets a context-respecting collector report ctx.Err() (and any partial data)
// rather than a generic timeout; only a genuinely stuck collector waits it out.
const collectGrace = 500 * time.Millisecond

type Collector interface {
	Name() string
	Timeout() time.Duration
	Collect(ctx context.Context) (any, error)
}

type Result struct {
	Name     string
	Data     any
	Err      error
	Duration time.Duration
	// NotRecorded is set only during `dsd replay`: the collector touched an input
	// the bundle never recorded (source.ErrNotRecorded), so what it could not
	// check is a recording gap, not a host finding.
	NotRecorded bool
}

// GapCount, when set (by `dsd replay`), returns how many inputs the replay source
// has refused so far because the bundle never recorded them. RunAll then runs the
// collectors one at a time so each Result can say whether IT hit a gap
// (Result.NotRecorded); replay is a pure function of the bundle, so serial costs
// little. Nil on a live run, which stays concurrent.
var GapCount func() int

func RunAll(ctx context.Context, collectors []Collector) <-chan Result {
	ch := make(chan Result, len(collectors))
	if GapCount != nil {
		gaps := GapCount
		go func() {
			defer close(ch)
			for _, c := range collectors {
				before := gaps()
				r := runOne(ctx, c)
				r.NotRecorded = gaps() > before
				ch <- r
			}
		}()
		return ch
	}
	var wg sync.WaitGroup
	for _, c := range collectors {
		wg.Add(1)
		go func(c Collector) {
			defer wg.Done()
			ch <- runOne(ctx, c)
		}(c)
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch
}

// runOne runs one collector under its own timeout and returns its Result.
func runOne(ctx context.Context, c Collector) Result {
	tctx, cancel := context.WithTimeout(ctx, c.Timeout())
	defer cancel()

	debug.Logf(ctx, "Runner", "start  %s  (timeout=%s)", c.Name(), c.Timeout())
	start := time.Now()

	// Run Collect in its own goroutine and bound it with a select on
	// tctx. A collector that ignores its context (a blocking syscall on a
	// stale mount, a wedged exec) must NOT be able to hang the whole run:
	// without this, that goroutine never returns, wg.Wait never completes,
	// the channel never closes, and the consumer blocks forever. The
	// buffered done channel lets an abandoned Collect finish and exit
	// later without leaking on a send to a gone receiver. (If the syscall
	// is truly unkillable, that one goroutine stays parked until the
	// process exits — bounded, and far better than hanging everything.)
	done := make(chan Result, 1)
	go func() {
		// A panicking collector (nil deref on an unexpected parse
		// result, index out of range, etc.) must not take down the
		// whole run — Go's default unhandled-panic behavior kills the
		// entire process, which would silently drop every other
		// collector's already-good results and exit with a status
		// that collides with a real CRIT. Recovering here turns it
		// into an ordinary Result.Err, exactly like a timeout, so it
		// flows through analysis.ApplyThresholds into an Unverified
		// insight the same way any other collector failure does.
		defer func() {
			if rec := recover(); rec != nil {
				done <- Result{Name: c.Name(), Err: fmt.Errorf("collector %s panicked: %v", c.Name(), rec)}
			}
		}()
		data, err := c.Collect(tctx)
		done <- Result{Name: c.Name(), Data: data, Err: err}
	}()

	var r Result
	select {
	case r = <-done:
		// Collector returned on its own (success or its own error).
	case <-tctx.Done():
		// Deadline hit (or parent cancelled). A context-respecting
		// collector returns its own result (often ctx.Err()) within a
		// short grace — prefer that. Only a collector genuinely stuck on
		// an uncancellable call gets the synthesized timeout, which keeps
		// the run bounded and the channel closing.
		select {
		case r = <-done:
		case <-time.After(collectGrace):
			r = Result{
				Name: c.Name(),
				Err:  fmt.Errorf("collector %s timed out after %s: %w", c.Name(), c.Timeout(), context.DeadlineExceeded),
			}
		}
	}
	r.Duration = time.Since(start)

	debug.Log(ctx, "Runner", "finish "+c.Name(), "dur", r.Duration.Round(time.Millisecond), "err", r.Err)
	return r
}
