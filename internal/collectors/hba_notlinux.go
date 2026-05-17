//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type HBACollector struct{}

func NewHBACollector() *HBACollector           { return &HBACollector{} }
func (c *HBACollector) Name() string           { return "HBA" }
func (c *HBACollector) Timeout() time.Duration { return 3 * time.Second }

func (c *HBACollector) Collect(_ context.Context) (interface{}, error) {
	return &models.HBAInfo{}, nil
}

func IsHBAPresent() bool { return false }
