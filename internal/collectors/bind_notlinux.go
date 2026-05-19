//go:build !linux

package collectors

import (
	"context"
	"time"
)

type BINDCollector struct{}

func NewBINDCollector() *BINDCollector          { return &BINDCollector{} }
func (c *BINDCollector) Name() string           { return "BIND" }
func (c *BINDCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *BINDCollector) Collect(_ context.Context) (interface{}, error) {
	return nil, nil
}
