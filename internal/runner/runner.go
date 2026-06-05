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
	Collect(ctx context.Context) (interface{}, error)
}

type Result struct {
	Name     string
	Data     interface{}
	Err      error
	Duration time.Duration
}

func RunAll(ctx context.Context, collectors []Collector) <-chan Result {
	ch := make(chan Result, len(collectors))
	var wg sync.WaitGroup

	for _, c := range collectors {
		wg.Add(1)
		go func(c Collector) {
			defer wg.Done()
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
						Err:  fmt.Errorf("collector %s timed out after %s", c.Name(), c.Timeout()),
					}
				}
			}
			r.Duration = time.Since(start)

			debug.Log(ctx, "Runner", "finish "+c.Name(), "dur", r.Duration.Round(time.Millisecond), "err", r.Err)
			ch <- r
		}(c)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch
}
