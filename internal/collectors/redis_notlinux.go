//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// RedisAvailable is false off Linux — the local-socket/PING probe is Linux-only.
func RedisAvailable() bool { return false }

type RedisCollector struct{}

func NewRedisCollector() *RedisCollector { return &RedisCollector{} }

func (c *RedisCollector) Name() string           { return "Redis" }
func (c *RedisCollector) Timeout() time.Duration { return time.Second }
func (c *RedisCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.RedisInfo{Detected: false}, nil
}
