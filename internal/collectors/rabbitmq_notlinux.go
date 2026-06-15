//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// RabbitMQAvailable is false off Linux — the probe is Linux-only.
func RabbitMQAvailable() bool { return false }

type RabbitMQCollector struct{}

func NewRabbitMQCollector() *RabbitMQCollector { return &RabbitMQCollector{} }

func (c *RabbitMQCollector) Name() string           { return "RabbitMQ" }
func (c *RabbitMQCollector) Timeout() time.Duration { return time.Second }
func (c *RabbitMQCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.RabbitMQInfo{Detected: false}, nil
}
