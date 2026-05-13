//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// HardwareCollector is a no-op on non-Linux platforms.
type HardwareCollector struct{}

func NewHardwareCollector() *HardwareCollector { return &HardwareCollector{} }

func (c *HardwareCollector) Name() string           { return "Hardware" }
func (c *HardwareCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *HardwareCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.HardwareInfo{}, nil
}
