//go:build linux

package collectors

import (
	"context"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// collectDarwin is never called on Linux — stub satisfies the compiler.
func (c *DiskCollector) collectDarwin(ctx context.Context) (*models.DiskInfo, error) {
	return c.collectDarwinBase(ctx)
}
