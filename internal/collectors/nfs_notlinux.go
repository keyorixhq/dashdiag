//go:build !linux

package collectors

import (
	"context"
	"time"
)

type NFSCollector struct{}

func NewNFSCollector() *NFSCollector           { return &NFSCollector{} }
func (c *NFSCollector) Name() string           { return "NFS" }
func (c *NFSCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *NFSCollector) Collect(_ context.Context) (interface{}, error) {
	return nil, nil // NFS checks are Linux-only
}
