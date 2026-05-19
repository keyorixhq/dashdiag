//go:build !linux && !darwin

package collectors

import (
	"context"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// collectLinuxExtras is a no-op on non-Linux, non-Darwin platforms.
func (c *DiskCollector) collectLinuxExtras(_ *models.DiskInfo) {}

// collectDarwin falls back to base on non-Darwin platforms (never called in practice).
func (c *DiskCollector) collectDarwin(ctx context.Context) (*models.DiskInfo, error) {
	return c.collectDarwinBase(ctx)
}
