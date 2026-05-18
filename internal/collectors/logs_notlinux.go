//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// LogsCollector is a no-op on non-Linux platforms.
type LogsCollector struct {
	Lookback time.Duration
}

func NewLogsCollector() *LogsCollector {
	return &LogsCollector{Lookback: 1 * time.Hour}
}

func NewLogsCollectorWithLookback(d time.Duration) *LogsCollector {
	return &LogsCollector{Lookback: d}
}

func (c *LogsCollector) Name() string           { return "Logs" }
func (c *LogsCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *LogsCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.LogsInfo{}, nil // Available=false → row hidden on macOS
}
