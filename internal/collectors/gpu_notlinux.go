//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// GPUCollector is a no-op on non-Linux platforms.
type GPUCollector struct {
	// Deep mirrors the Linux collector field so callers compile cross-platform.
	Deep bool
}

func NewGPUCollector() *GPUCollector     { return &GPUCollector{} }
func NewGPUDeepCollector() *GPUCollector { return &GPUCollector{Deep: true} }

func (c *GPUCollector) Name() string           { return "GPU" }
func (c *GPUCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *GPUCollector) Collect(_ context.Context) (any, error) {
	return &models.GPUInfo{}, nil
}
