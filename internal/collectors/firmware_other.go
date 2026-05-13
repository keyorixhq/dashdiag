//go:build !linux && !darwin

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type FirmwareCollector struct{}

func NewFirmwareCollector() *FirmwareCollector { return &FirmwareCollector{} }

func (c *FirmwareCollector) Name() string           { return "Firmware" }
func (c *FirmwareCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *FirmwareCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.FirmwareInfo{Status: "unavailable"}, nil
}
