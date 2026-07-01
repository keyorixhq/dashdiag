//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type HWRaidCollector struct{}

func NewHWRaidCollector() *HWRaidCollector        { return &HWRaidCollector{} }
func (c *HWRaidCollector) Name() string           { return "HardwareRAID" }
func (c *HWRaidCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *HWRaidCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.HWRaidInfo{}, nil
}

func IsHWRaidPresent() bool { return false }
