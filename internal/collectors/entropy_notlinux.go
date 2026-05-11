//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// EntropyCollector is a no-op on non-Linux platforms.
// /proc/sys/kernel/random/entropy_avail is Linux-only.
type EntropyCollector struct{}

func NewEntropyCollector() *EntropyCollector { return &EntropyCollector{} }

func (c *EntropyCollector) Name() string           { return "Entropy" }
func (c *EntropyCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *EntropyCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.EntropyInfo{Available: -1, PoolSize: -1}, nil
}
