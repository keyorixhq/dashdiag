package collectors

import (
	"context"
	"time"
)

// SnapperCollector wraps CollectSnapper for the runner pipeline.
// Only meaningful on Linux with snapper installed (SLES/openSUSE).
// On other platforms CollectSnapper returns an empty struct — no cost.
type SnapperCollector struct{}

func NewSnapperCollector() *SnapperCollector { return &SnapperCollector{} }

func (c *SnapperCollector) Name() string           { return "Snapshots" }
func (c *SnapperCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *SnapperCollector) Collect(ctx context.Context) (interface{}, error) {
	return CollectSnapper(ctx)
}
