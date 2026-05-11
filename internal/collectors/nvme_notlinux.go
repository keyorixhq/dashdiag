//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// NVMeCollector is a no-op on non-Linux platforms.
type NVMeCollector struct{}

func NewNVMeCollector() *NVMeCollector { return &NVMeCollector{} }

func (c *NVMeCollector) Name() string           { return "NVMe" }
func (c *NVMeCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *NVMeCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.NVMeInfo{}, nil
}
