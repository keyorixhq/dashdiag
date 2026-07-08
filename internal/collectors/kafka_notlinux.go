//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// KafkaAvailable is false off Linux — the probe is Linux-only.
func KafkaAvailable() bool { return false }

type KafkaCollector struct{}

func NewKafkaCollector() *KafkaCollector { return &KafkaCollector{} }

func (c *KafkaCollector) Name() string           { return "Kafka" }
func (c *KafkaCollector) Timeout() time.Duration { return time.Second }
func (c *KafkaCollector) Collect(_ context.Context) (any, error) {
	return &models.KafkaInfo{Detected: false}, nil
}
