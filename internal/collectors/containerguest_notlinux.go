//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type ContainerGuestCollector struct{}

func NewContainerGuestCollector() *ContainerGuestCollector { return &ContainerGuestCollector{} }

func (c *ContainerGuestCollector) Name() string           { return "ContainerGuest" }
func (c *ContainerGuestCollector) Timeout() time.Duration { return 1 * time.Second }

func (c *ContainerGuestCollector) Collect(_ context.Context) (any, error) {
	return &models.ContainerGuestInfo{}, nil
}

// ContainerGuestAvailable is always false off Linux — container cgroup signals are
// Linux-only.
func ContainerGuestAvailable() bool { return false }
