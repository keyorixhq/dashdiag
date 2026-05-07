package collectors

import (
	"context"
	"time"
)

// Collector matches runner.Collector exactly.
type Collector interface {
	Name() string
	Timeout() time.Duration
	Collect(ctx context.Context) (interface{}, error)
}
