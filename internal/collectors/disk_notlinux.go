//go:build !linux

package collectors

import "github.com/keyorixhq/dashdiag/internal/models"

// collectLinuxExtras is a no-op on non-Linux platforms.
func (c *DiskCollector) collectLinuxExtras(_ *models.DiskInfo) {}
