//go:build !linux && !darwin

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// BatteryCollector is a no-op on unsupported platforms.
type BatteryCollector struct{}

func NewBatteryCollector() *BatteryCollector { return &BatteryCollector{} }

func (c *BatteryCollector) Name() string           { return "Battery" }
func (c *BatteryCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *BatteryCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.BatteryInfo{}, nil
}
