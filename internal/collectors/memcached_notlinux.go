//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// MemcachedAvailable is false off Linux — the probe is Linux-only.
func MemcachedAvailable() bool { return false }

type MemcachedCollector struct{}

func NewMemcachedCollector() *MemcachedCollector { return &MemcachedCollector{} }

func (c *MemcachedCollector) Name() string           { return "Memcached" }
func (c *MemcachedCollector) Timeout() time.Duration { return time.Second }
func (c *MemcachedCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.MemcachedInfo{Detected: false}, nil
}
