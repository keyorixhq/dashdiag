//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type NUMACollector struct{}

func NewNUMACollector() *NUMACollector          { return &NUMACollector{} }
func (c *NUMACollector) Name() string           { return "NUMA" }
func (c *NUMACollector) Timeout() time.Duration { return 2 * time.Second }

func (c *NUMACollector) Collect(_ context.Context) (interface{}, error) {
	return &models.NUMAInfo{}, nil
}

func IsNUMAPresent() bool { return false }
