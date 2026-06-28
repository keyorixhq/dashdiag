//go:build !linux

package collectors

import (
	"context"
	"time"
)

type RootFSCollector struct{}

func NewRootFSCollector() *RootFSCollector        { return &RootFSCollector{} }
func (c *RootFSCollector) Name() string           { return "Root FS" }
func (c *RootFSCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *RootFSCollector) Collect(_ context.Context) (interface{}, error) {
	return nil, nil // /proc/mounts + remount-ro semantics are Linux-only
}
