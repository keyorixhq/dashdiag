//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type VMwareCollector struct{}

func NewVMwareCollector() *VMwareCollector { return &VMwareCollector{} }

func (c *VMwareCollector) Name() string           { return "VMware" }
func (c *VMwareCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *VMwareCollector) Collect(_ context.Context) (interface{}, error) {
	return &models.VMwareInfo{}, nil
}

// VMwareGuestAvailable is always false off Linux — the guest-config checks read
// Linux DMI/sysfs/procfs paths that don't exist elsewhere.
func VMwareGuestAvailable() bool { return false }
