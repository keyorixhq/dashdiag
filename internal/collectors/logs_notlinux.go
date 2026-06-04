//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// LogsCollector is a no-op on non-Linux platforms.
type LogsCollector struct {
	Lookback time.Duration
	profile  platform.Profile
}

func NewLogsCollector() *LogsCollector {
	return &LogsCollector{Lookback: 1 * time.Hour}
}

func NewLogsCollectorWithLookback(d time.Duration) *LogsCollector {
	return &LogsCollector{Lookback: d}
}

// NewLogsCollectorWithProfile mirrors the Linux constructor; the profile is
// unused on non-Linux platforms where the collector is a no-op.
func NewLogsCollectorWithProfile(p platform.Profile) *LogsCollector {
	return &LogsCollector{Lookback: 1 * time.Hour, profile: p}
}

func (c *LogsCollector) Name() string           { return "Logs" }
func (c *LogsCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *LogsCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.LogsInfo{}, nil // Available=false → row hidden on macOS
}
