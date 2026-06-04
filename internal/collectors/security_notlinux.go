//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// SecurityCollector is a no-op on non-Linux platforms.
type SecurityCollector struct {
	profile platform.Profile
}

func NewSecurityCollector() *SecurityCollector { return &SecurityCollector{} }

// NewSecurityCollectorWithProfile mirrors the Linux constructor; the profile is
// unused on non-Linux platforms where the collector is a no-op.
func NewSecurityCollectorWithProfile(p platform.Profile) *SecurityCollector {
	return &SecurityCollector{profile: p}
}

func (c *SecurityCollector) Name() string           { return "Hardening" }
func (c *SecurityCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *SecurityCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.SecurityInfo{}, nil
}

// CollectSUSEConnect is a no-op on non-Linux platforms.
func CollectSUSEConnect(_ context.Context, _ *models.SecurityInfo) {}
