//go:build !linux

package collectors

import (
	"context"
	"time"
)

type FstabDriftCollector struct{}

func NewFstabDriftCollector() *FstabDriftCollector    { return &FstabDriftCollector{} }
func (c *FstabDriftCollector) Name() string           { return "Fstab" }
func (c *FstabDriftCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *FstabDriftCollector) Collect(_ context.Context) (interface{}, error) {
	return nil, nil // /etc/fstab + udev tag symlinks are Linux-only
}

// FstabAvailable is always false off Linux.
func FstabAvailable() bool { return false }
