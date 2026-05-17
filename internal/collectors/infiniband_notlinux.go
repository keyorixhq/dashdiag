//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type InfiniBandCollector struct{}

func NewInfiniBandCollector() *InfiniBandCollector    { return &InfiniBandCollector{} }
func (c *InfiniBandCollector) Name() string           { return "InfiniBand" }
func (c *InfiniBandCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *InfiniBandCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.InfiniBandInfo{}, nil
}

func IsInfiniBandPresent() bool { return false }
