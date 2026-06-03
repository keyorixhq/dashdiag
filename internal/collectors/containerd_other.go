//go:build !linux

package collectors

import (
	"context"
	"time"
)

// ContainerdAvailable always returns false on non-Linux — containerd is
// Linux-only. Keeps cmd/health.go gate compilable on darwin/windows.
func ContainerdAvailable() bool { return false }

// ContainerdCollector is a no-op on non-Linux.
type ContainerdCollector struct{}

func NewContainerdCollector() *ContainerdCollector { return &ContainerdCollector{} }

func (c *ContainerdCollector) Name() string           { return "Containerd" }
func (c *ContainerdCollector) Timeout() time.Duration { return 5 * time.Second }
func (c *ContainerdCollector) Collect(_ context.Context) (interface{}, error) {
	return nil, nil
}
