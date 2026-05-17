//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func IsRAIDPresent() bool { return false }

type RAIDCollector struct{}

func NewRAIDCollector() *RAIDCollector { return &RAIDCollector{} }

func (c *RAIDCollector) Name() string           { return "RAID" }
func (c *RAIDCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *RAIDCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.RAIDInfo{}, nil
}
