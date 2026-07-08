//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type KVMGuestCollector struct{}

func NewKVMGuestCollector() *KVMGuestCollector { return &KVMGuestCollector{} }

func (c *KVMGuestCollector) Name() string           { return "KVMGuest" }
func (c *KVMGuestCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *KVMGuestCollector) Collect(_ context.Context) (any, error) {
	return &models.KVMGuestInfo{}, nil
}

// KVMGuestAvailable is always false off Linux — the guest-config checks read
// Linux DMI/sysfs/procfs paths that don't exist elsewhere.
func KVMGuestAvailable() bool { return false }
