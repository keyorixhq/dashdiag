//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type TimelineCollector struct{ WindowHours int }

func NewTimelineCollector(hours int) *TimelineCollector {
	return &TimelineCollector{WindowHours: hours}
}
func (c *TimelineCollector) Name() string           { return "Timeline" }
func (c *TimelineCollector) Timeout() time.Duration { return 1 * time.Second }
func (c *TimelineCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.TimelineInfo{WindowHours: c.WindowHours}, nil
}
