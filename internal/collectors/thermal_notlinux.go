//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ThermalCollector is a no-op on non-Linux platforms.
type ThermalCollector struct {
	InContainer bool
}

func NewThermalCollector() *ThermalCollector { return &ThermalCollector{} }

func NewThermalCollectorWithContext(inContainer bool) *ThermalCollector {
	return &ThermalCollector{InContainer: inContainer}
}

func (c *ThermalCollector) Name() string           { return "CPU Thermal" }
func (c *ThermalCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *ThermalCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.ThermalInfo{}, nil
}
