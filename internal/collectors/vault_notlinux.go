//go:build !linux

package collectors

import (
	"context"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// VaultAvailable is false off Linux — the probe is Linux-only.
func VaultAvailable() bool { return false }

type VaultCollector struct{}

func NewVaultCollector() *VaultCollector { return &VaultCollector{} }

func (c *VaultCollector) Name() string           { return "Vault" }
func (c *VaultCollector) Timeout() time.Duration { return time.Second }
func (c *VaultCollector) Collect(_ context.Context) (any, error) {
	return &models.VaultInfo{Available: false}, nil
}
