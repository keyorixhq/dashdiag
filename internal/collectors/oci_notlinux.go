//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type OCICollector struct{}

func NewOCICollector() *OCICollector { return &OCICollector{} }

func (c *OCICollector) Name() string           { return "OCI" }
func (c *OCICollector) Timeout() time.Duration { return 1 * time.Second }

func (c *OCICollector) Collect(_ context.Context) (interface{}, error) {
	return &models.OCIInfo{}, nil
}

// OCIGuestAvailable is always false off Linux — the OCI guest checks read Linux
// DMI/sysfs paths and Linux-only tools (systemctl, chronyc, ethtool) that don't
// exist elsewhere.
func OCIGuestAvailable() bool { return false }
