//go:build !linux && !darwin

package collectors

import "github.com/keyorixhq/dashdiag/internal/models"

// collectLinuxExtras is a no-op on non-Linux, non-Darwin platforms.
func (c *DiskCollector) collectLinuxExtras(_ *models.DiskInfo) {}
