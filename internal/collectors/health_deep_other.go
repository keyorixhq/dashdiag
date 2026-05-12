//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// HealthDeepCollector stub for non-Linux platforms.
type HealthDeepCollector struct{}

func NewHealthDeepCollector() *HealthDeepCollector { return &HealthDeepCollector{} }

func (c *HealthDeepCollector) Name() string           { return "CPUDeep" }
func (c *HealthDeepCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *HealthDeepCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.HealthDeepInfo{
		Status:       "unavailable",
		StatusReason: "per-core CPU breakdown not available on this platform",
	}, nil
}
