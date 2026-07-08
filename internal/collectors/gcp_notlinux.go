//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type GCPCollector struct{}

func NewGCPCollector() *GCPCollector { return &GCPCollector{} }

func (c *GCPCollector) Name() string           { return "GCP" }
func (c *GCPCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *GCPCollector) Collect(_ context.Context) (any, error) {
	return &models.GCPInfo{}, nil
}

// GCPGuestAvailable is always false off Linux — the GCE guest checks read Linux
// DMI/sysfs paths and Linux-only service state that don't exist elsewhere.
func GCPGuestAvailable() bool { return false }
