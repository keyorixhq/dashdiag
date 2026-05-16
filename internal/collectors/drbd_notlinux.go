//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type DRBDCollector struct{}

func NewDRBDCollector() *DRBDCollector { return &DRBDCollector{} }

func (c *DRBDCollector) Name() string           { return "DRBD" }
func (c *DRBDCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *DRBDCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.DRBDInfo{}, nil
}
