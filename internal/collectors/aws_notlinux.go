//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type AWSCollector struct{}

func NewAWSCollector() *AWSCollector { return &AWSCollector{} }

func (c *AWSCollector) Name() string           { return "AWS" }
func (c *AWSCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *AWSCollector) Collect(_ context.Context) (any, error) {
	return &models.AWSInfo{}, nil
}

// AWSGuestAvailable is always false off Linux — the EC2 guest checks read Linux
// DMI/sysfs/procfs paths and Linux-only tools (ethtool, nvme) that don't exist
// elsewhere.
func AWSGuestAvailable() bool { return false }
