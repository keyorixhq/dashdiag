//go:build darwin

package collectors

import "github.com/keyorixhq/dashdiag/internal/models"

// collectLinuxExtras is a no-op on Darwin — physical drive collection
// is handled by collectDarwinDrives() called from collectDarwin().
func (c *DiskCollector) collectLinuxExtras(_ *models.DiskInfo) {}
