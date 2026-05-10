package runner

import (
	"context"
	"sync"
	"time"

	"github.com/keyorixhq/dashdiag/internal/debug"
)

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
			data, err := c.Collect(tctx)
			dur := time.Since(start)
			if err != nil {
				debug.Log(ctx, "Runner", "finish "+c.Name(), "dur", dur.Round(time.Millisecond), "err", err)
			} else {
				debug.Log(ctx, "Runner", "finish "+c.Name(), "dur", dur.Round(time.Millisecond), "err", nil)
			}
			ch <- Result{
				Name:     c.Name(),
				Data:     data,
				Err:      err,
				Duration: dur,
			}
		}(c)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch
}
