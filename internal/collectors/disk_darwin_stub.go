//go:build darwin

package collectors

import (
	"context"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// collectLinuxExtras is a no-op on Darwin — physical drive collection
// is handled by collectDarwinDrives() called from collectDarwin().
func (c *DiskCollector) collectLinuxExtras(_ context.Context, _ *models.DiskInfo) { /* no-op */ }
