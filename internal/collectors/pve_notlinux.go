//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type PVECollector struct{}

func NewPVECollector() *PVECollector { return &PVECollector{} }

func (c *PVECollector) Name() string           { return "PVE" }
func (c *PVECollector) Timeout() time.Duration { return 1 * time.Second }

func (c *PVECollector) Collect(_ context.Context) (interface{}, error) {
	return &models.PVEInfo{}, nil
}
