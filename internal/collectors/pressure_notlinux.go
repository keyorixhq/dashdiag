//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type PressureCollector struct{}

func NewPressureCollector() *PressureCollector      { return &PressureCollector{} }
func (c *PressureCollector) Name() string           { return "Pressure" }
func (c *PressureCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *PressureCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.PressureInfo{}, nil
}

func IsPSIAvailable() bool { return false }
